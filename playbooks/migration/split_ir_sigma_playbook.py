#!/usr/bin/env python3
"""
split_ir_sigma_playbook.py — Migration/Parsing Layer for the Suburban-SOC
dynamic-HTML playbook system.

Splits docs/playbooks/IR_Sigma_Playbook.md into one structured JSON record
per rule (playbooks/data/<rule_id>.json), matching the schema at
playbooks/schema/playbook.schema.json.

Design choice (documented per audit fix #1 / #6): each of the 5 fixed
subsections (Rule Summary & MITRE Mapping / Automated Extraction Fields /
Enrichment Criteria / Containment Decision Flow / Remediation & Evidence
Preservation) is captured as a single 'markdown' block holding that
subsection's raw Markdown body verbatim, rather than being decomposed further
into typed sub-blocks (table/list/codeBlock). The source mixes prose, tables,
nested lists and fenced code within a subsection in ways that are lossy to
split automatically without per-rule manual review (560KB, 123 entries).
Preserving each subsection verbatim guarantees "preserve commands exactly"
and "do not silently discard content" (build-prompt Phase 8) over a more
granular structure that cannot yet be verified lossless at this scale.

This is documented as a known limitation, not hidden — see
docs/playbook-migration-report.md.

Also runs a rerunnable drift check: if IR_Sigma_Playbook.md changes after
data/ files are generated, re-running this script overwrites them and the
migration report's "last synced" dates change, so drift is visible via git
diff (audit fix #6).

Usage:
    python3 playbooks/migration/split_ir_sigma_playbook.py [--check]

    --check   Do not write files. Exit 1 if regenerating would change any
              existing playbooks/data/*.json (drift check for CI/pre-archive
              use, per audit fix #6). Prints which ids differ.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from datetime import date, timezone, datetime
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE_MD = REPO_ROOT / "docs" / "playbooks" / "IR_Sigma_Playbook.md"
DATA_DIR = REPO_ROOT / "playbooks" / "data"
ENUMS_PATH = REPO_ROOT / "playbooks" / "schema" / "enums.json"

FAMILY_RE = re.compile(r"^#### (?P<title>.+?)(?:\s+—\s+\d+\s+rules?)?\s*$")
ANCHOR_RE = re.compile(r'^<a id="(?P<id>[^"]+)"></a>\s*$')
RULE_TITLE_RE = re.compile(r"^##### (?P<title>.+)$")
META_RE = re.compile(
    r"^\*\*Rule file:\*\*\s*`(?P<rule_file>[^`]+)`\s*·\s*"
    r"\*\*Status:\*\*\s*(?P<status>\S+)\s*·\s*"
    r"\*\*Severity:\*\*\s*(?P<severity>\S+)\s*$"
)
SUBSECTION_RE = re.compile(r"^###### (?P<num>\d)\.\s+(?P<title>.+)$")

SUBSECTION_IDS = {
    1: "rule-summary-mitre-mapping",
    2: "automated-extraction-fields",
    3: "enrichment-criteria",
    4: "containment-decision-flow",
    5: "remediation-evidence-preservation",
}

# Non-rule anchors present in the source that must NOT be treated as rule ids.
NON_RULE_ANCHORS = {
    "how-to-use-this-playbook",
    "master-detection--response-matrix",
    "standard-4-phase-ir-workflow",
}

# Family heading text -> enums.json category value.
FAMILY_TO_CATEGORY = {
    "Windows Process Creation (Sysmon EID 1)": "Windows Process Creation",
    "Windows Security Log - Authentication & Identity": "Windows Security Log - Authentication & Identity",
    "Windows Security Log — Authentication & Identity": "Windows Security Log - Authentication & Identity",
    "PowerShell Script Block Logging (EID 4104)": "PowerShell Script Block Logging",
    "Windows System Log - Service Control Manager & Event Log Service": "Windows System Log - Service Control Manager & Event Log Service",
    "Windows System Log — Service Control Manager & Event Log Service": "Windows System Log - Service Control Manager & Event Log Service",
    "Zeek Network Telemetry": "Zeek Network Telemetry",
    "Linux Authentication (auth.log)": "Linux Authentication",
    "Linux Process Creation (auditd execve, #442)": "Linux Process Creation",
    "Sysmon Specialized Events (EID 8 CreateRemoteThread, EID 11 FileCreate)": "Sysmon Specialized Events",
    "WMI Activity (EID 5861)": "WMI Activity",
}


def normalize_family_title(raw: str) -> str:
    # Strip the em-dash "— N rules" suffix variations and normalize dash type.
    raw = re.sub(r"\s*[—-]\s*\d+\s+rules?\s*$", "", raw).strip()
    return raw


def extract_mitre(subsection1_text: str) -> dict:
    tactics: list[str] = []
    techniques: list[str] = []
    for line in subsection1_text.splitlines():
        m = re.match(r"^\|\s*Tactic\(s\)\s*\|\s*(.+?)\s*\|\s*$", line)
        if m:
            tactics = [t.strip() for t in m.group(1).split(",")]
        m = re.match(r"^\|\s*Technique\(s\)\s*\|\s*(.+?)\s*\|\s*$", line)
        if m:
            techniques = [m.group(1).strip()]
    return {"tactics": tactics, "techniques": techniques}


def parse(source_text: str) -> tuple[list[dict], list[str]]:
    """Returns (records, warnings)."""
    lines = source_text.splitlines()
    records: list[dict] = []
    warnings: list[str] = []

    current_family = None
    current_category = None
    i = 0
    n = len(lines)

    pending_anchor_id = None

    while i < n:
        line = lines[i]

        fam_m = FAMILY_RE.match(line)
        if fam_m:
            current_family = normalize_family_title(fam_m.group("title"))
            current_category = FAMILY_TO_CATEGORY.get(current_family)
            if current_category is None:
                warnings.append(
                    f"Unmapped family heading (no category enum match): {current_family!r} at line {i+1}"
                )
            i += 1
            continue

        anchor_m = ANCHOR_RE.match(line)
        if anchor_m:
            pending_anchor_id = anchor_m.group("id")
            i += 1
            continue

        title_m = RULE_TITLE_RE.match(line)
        if title_m:
            if pending_anchor_id is None:
                warnings.append(f"Rule heading with no preceding anchor id at line {i+1}: {title_m.group('title')!r}")
                i += 1
                continue
            rule_id = pending_anchor_id
            pending_anchor_id = None

            if rule_id in NON_RULE_ANCHORS:
                i += 1
                continue

            rule_title = title_m.group("title").strip()
            i += 1

            # Next non-blank line should be the metadata line.
            while i < n and lines[i].strip() == "":
                i += 1
            if i >= n or not META_RE.match(lines[i]):
                warnings.append(f"Rule {rule_id!r}: missing/malformed metadata line after heading (line {i+1})")
                meta = {"rule_file": "", "status": "experimental", "severity": "medium"}
            else:
                meta = META_RE.match(lines[i]).groupdict()
                i += 1

            # Collect subsections until the next family heading, anchor, or EOF.
            subsections: dict[int, list[str]] = {n: [] for n in SUBSECTION_IDS}
            current_sub = None
            while i < n:
                nxt = lines[i]
                if FAMILY_RE.match(nxt) or ANCHOR_RE.match(nxt):
                    break
                sub_m = SUBSECTION_RE.match(nxt)
                if sub_m:
                    current_sub = int(sub_m.group("num"))
                    i += 1
                    continue
                if current_sub is not None:
                    subsections[current_sub].append(nxt)
                i += 1

            sections = []
            for num in range(1, 6):
                sub_id = SUBSECTION_IDS[num]
                body = "\n".join(subsections[num]).strip("\n")
                if not body:
                    warnings.append(f"Rule {rule_id!r}: subsection {num} ({sub_id}) is empty")
                sections.append({
                    "id": sub_id,
                    "title": sub_id.replace("-", " ").title(),
                    "type": "procedure" if num == 4 else "reference",
                    "blocks": [{"blockType": "markdown", "content": body}] if body else [],
                })

            evidence = []
            remediation_body = "\n".join(subsections[5])
            for m in re.finditer(r"^- (.+)$", remediation_body, re.MULTILINE):
                text = m.group(1).strip()
                if re.search(r"\b(acquire|collect|hash|preserve|export|record|image)\b", text, re.IGNORECASE):
                    evidence.append(text)

            mitre = extract_mitre("\n".join(subsections[1]))

            record = {
                "id": rule_id,
                "title": rule_title,
                "ruleFile": meta["rule_file"],
                "status": meta["status"],
                "severity": meta["severity"],
                "category": current_category or (current_family or "unknown"),
                "version": "1.0",
                "lastUpdated": date.today().isoformat(),
                "tags": [current_category] if current_category else [],
                "integrations": [],
                "mitre": mitre,
                "aiContext": {
                    "playbook": rule_id,
                    "dataSource": "",
                    "triggerCondition": "",
                },
                "sections": sections,
                "evidence": evidence,
                "unmappedContent": [],
            }
            records.append(record)
            continue

        i += 1

    return records, warnings


def load_valid_ids() -> set[str]:
    ids = set()
    for pattern in ("rules/sigma/*.yml", "rules/suricata/*.rules"):
        for p in (REPO_ROOT).glob(pattern):
            ids.add(p.stem)
    return ids


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--check", action="store_true", help="Drift check only; do not write.")
    args = ap.parse_args()

    if not SOURCE_MD.exists():
        print(f"ERROR: source file not found: {SOURCE_MD}", file=sys.stderr)
        sys.exit(2)

    source_text = SOURCE_MD.read_text(encoding="utf-8")
    records, warnings = parse(source_text)

    valid_ids = load_valid_ids()
    parsed_ids = {r["id"] for r in records}

    missing_playbooks = sorted(valid_ids - parsed_ids)
    orphan_playbooks = sorted(parsed_ids - valid_ids)

    print(f"Parsed {len(records)} playbook entries from {SOURCE_MD.relative_to(REPO_ROOT)}")
    if warnings:
        print(f"\n{len(warnings)} parse warnings:")
        for w in warnings:
            print(f"  - {w}")
    if missing_playbooks:
        print(f"\n{len(missing_playbooks)} rule files with NO playbook entry (not migrated — flagged, not fabricated):")
        for rid in missing_playbooks:
            print(f"  - {rid}")
    if orphan_playbooks:
        print(f"\n{len(orphan_playbooks)} playbook entries with no matching rule file (orphaned):")
        for rid in orphan_playbooks:
            print(f"  - {rid}")

    if args.check:
        changed = []
        for r in records:
            out_path = DATA_DIR / f"{r['id']}.json"
            if not out_path.exists():
                changed.append(r["id"])
                continue
            existing = json.loads(out_path.read_text(encoding="utf-8"))
            # Compare ignoring lastUpdated (regenerated every run).
            existing_cmp = {k: v for k, v in existing.items() if k != "lastUpdated"}
            new_cmp = {k: v for k, v in r.items() if k != "lastUpdated"}
            if existing_cmp != new_cmp:
                changed.append(r["id"])
        if changed:
            print(f"\nDRIFT DETECTED in {len(changed)} record(s) — source changed since data/ was generated:")
            for rid in changed:
                print(f"  - {rid}")
            sys.exit(1)
        print("\nNo drift detected.")
        sys.exit(0)

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    for r in records:
        out_path = DATA_DIR / f"{r['id']}.json"
        out_path.write_text(json.dumps(r, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")

    print(f"\nWrote {len(records)} files to {DATA_DIR.relative_to(REPO_ROOT)}/")


if __name__ == "__main__":
    main()
