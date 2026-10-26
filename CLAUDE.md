# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

`AGENTS.md` (project overview, setup, security-sensitive areas) and `docs/CONVENTIONS.md` (shebangs, docstrings, date-stamped filenames) also apply. `.claude/commands/` holds the `sigma-rule`, `sigma-validate` and `triage` skills; use them for that work instead of improvising.

## Start of session

1. Read `plans/<latest>-session-handoff.md` and the top `LAST SESSION` section of `planned_execution.md`. They hold current status, open items in priority order, and owner decisions.
2. Work out which session kind you are in (see "Session kind decides what you can do") before promising anything that needs Docker, Elasticsearch, `gh` admin scopes or the wiki.
3. Never open a PR unless asked.

## Commands

Python 3.11 only (`requires-python = ">=3.11,<3.12"`; CI and the generated docs depend on it). Nothing is pip-installable; `pyproject.toml` only sets pytest's `pythonpath` so service modules import as flat top-level names (`app`, `agent`, `slo_metrics`, `env_loader`, `sigma_eval`, ...).

```bash
# Detection toolchain, pinned exactly as CI (pyparsing 3.3.3 breaks pysigma)
pip install sigma-cli==3.1.0 pysigma==1.5.0 pysigma-backend-elasticsearch==2.1.1 "pyparsing==3.3.2" pytest pyyaml requests
# SOAR suites (Flask/FastAPI, mocked network/ES/SSH)
pip install flask==3.1.3 requests==2.33.0 fastapi==0.121.1 uvicorn==0.34.0 pyyaml==6.0.2 asyncssh==2.18.0 httpx==0.28.1 pytest
# Reporting-plane coverage gate needs the full agent requirements + WeasyPrint native libs
pip install -r scripts/setup/ai_agent/requirements.txt pytest pytest-cov

pytest                                                   # whole tree from repo root
python -m pytest tests/detections/test_sigma_detections.py -q      # Sigma logic gate
python -m pytest tests/detections/test_sigma_detections.py -q -k "promotion_gate"   # one test
python -m pytest tests/pipeline -q                       # config/unit/systemd parity checks
python -m pytest tests/ai_agent/test_alert_auth.py -q    # HMAC auth, exclusion list, approval flow
cd scripts/hive-mind-broker && cp inventory.example.yaml inventory.yaml && python -m pytest test_app.py test_inventory.py -q   # broker tests need CWD + inventory
python tests/detections/test_threshold_rules.py          # threshold .ndjson <-> Sigma pairing
python tests/validate_emulation_map.py --no-color        # emulation_telemetry.map vs reality

# Every Sigma rule must convert through the ECS pipeline and never emit process.command_line
sigma convert -t lucene -f siem_rule_ndjson -p configs/detections/suburban-soc-ecs.yml rules/sigma/<rule>.yml

# Lint, exactly as CI (local ruff drift is a known trap: install this version)
pip install ruff==0.15.15 && ruff check .
git ls-files '*.py' | xargs mypy --ignore-missing-imports --follow-imports=silent
git ls-files '*.sh' | xargs shellcheck -S warning
yamllint -c .yamllint configs/
suricata -T -c configs/suricata/suricata.yaml -l /tmp/suricata-lint --af-packet=lo   # needs the suricata package
docker compose -f scripts/setup/docker-compose.yml config -q

# Generated docs: regenerate, never hand-edit; CI runs --check on both
python scripts/setup/build_attack_coverage.py            # docs/detections/attack-coverage.{json,md}
python scripts/setup/build_kql_docs.py                   # docs/detections/SIEM_KQL_Documentation.md
```

Live stack (local only): `cp scripts/setup/.env.example scripts/setup/.env`, fill the passwords, then `docker compose up -d` from `scripts/setup/`. `scripts/setup/soc_pipeline.sh` is the interactive SOP menu; `deploy_detections.sh` imports Sigma rules with `status: test|stable` only (`--include-experimental` overrides) plus `rules/elastic/threshold/*.ndjson`.

CI gates on every PR: `Detections CI`, `Lint`, `SOAR Tests`, `Reporting Plane Coverage` (70% line coverage on `slo_metrics`, `run_hunts`, `weekly_ciso_report`, `env_loader`, `es_client`), `Secret Scan` (gitleaks), `Security Scan` (pip-audit, Trivy), CodeQL. `main` requires 14 checks and only the owner merges. The `live-fire` job in `Detections CI` is the only one with a real Elasticsearch and Docker; it is deliberately not a required check.

## Architecture

Two planes, both multi-tenant (`tenant.id` on every event; per-tenant indices, roles and routing).

**Detection plane:** OpenWrt router → tcpdump over SSH → Zeek (native `/opt/zeek/bin/zeek` on the WSL capture host, `configs/zeek/local.zeek`, intel feed in `configs/intel/`) and Suricata (`configs/suricata/`, `rules/suricata/*.rules`) → Filebeat (`configs/network/`, `configs/endpoint/` for Winlogbeat/Filebeat on endpoints) → Logstash (`configs/logstash.conf`: grok, GeoIP, ECS mapping, Category 5 framework enrichment for Zeek-side detections like T1046/T1110, and the ingest-time HMAC `/alert` trigger) → Elasticsearch (`logstash-security-*`, `.alerts-security.alerts-*`, `soar-actions-*`; index templates in `configs/elasticsearch/`) → Kibana (dashboard exports in `configs/server/`). Capture, liveness, SLO, intel-refresh and checkpoint-compaction run as the systemd units in `configs/systemd/`; `scripts/setup/redeploy_systemd_units.sh` installs them.

**Response plane (SOAR):** `scripts/setup/ai_agent/agent_app.py` (Flask, port 5000) receives the HMAC-signed `/alert`, `agent.py` does LLM triage with ATT&CK mapping and drafts containment into an approval queue backed by `checkpoints.py`; `POST /approve` and `/pending` use a second HMAC credential and an atomic create-if-absent claim so an isolation runs at most once. Autonomous isolation only with `AUTONOMOUS_ISOLATION=true`, after the exclusion list. Approved blocks go to `scripts/hive-mind-broker/app.py` (FastAPI, port 8000), which checks HMAC + tenant scope and has `dispatcher.py` push nftables DROP rules over SSH to routers in `inventory.yaml` (gitignored; `inventory.example.yaml` is the test fixture). `playbooks_blueprint.py` serves read-only HTML playbooks from `playbooks/data/*.json`. Reporting lives beside the agent: `slo_metrics.py`, `weekly_ciso_report.py`, `scripts/setup/run_hunts.py` (hunts in `hunts/*.yml`), sharing `scripts/setup/lib/{env_loader,es_client}.py`.

### Detection-as-code: how a rule becomes "done"

A Sigma rule in `rules/sigma/` is bound to four other files, and CI fails if any is missing:

- `tests/detections/fixtures.json`, keyed by rule filename: exactly one `true_positive` object and a non-empty `true_negatives` list. Fixtures use Sigma field names (`Image`, `CommandLine`) and are evaluated by `tests/detections/sigma_eval.py`, a deliberate re-implementation of Sigma matching that tests rule logic only; the real Lucene query is only proven by `sigma convert` (CI) and `test_live_fire.py`. Its docstring records the Elasticsearch semantics it mirrors (full-string case-sensitive `re`, no `^`/`$` anchors, per-element matching of multi-value fields, bare equality on `text`-mapped fields like `message`). Read it before using a modifier the corpus does not already use.
- `docs/playbooks/IR_Sigma_Playbook.md`: an `<a id="<rule stem>"></a>` anchor, a `**Rule file:**` line, and a matrix link (`test_playbook_coverage.py`). Then regenerate `playbooks/data/` with `playbooks/migration/split_ir_sigma_playbook.py`.
- `configs/detections/emulation_telemetry.map` and `coverage_checklist.md` must stay row-for-row in sync (`test_coverage_checklist_sync.py`), with a matching `tests/anomaly_simulation/sim_*` script for the emulation.
- `docs/detections/attack-coverage.*` and `SIEM_KQL_Documentation.md`, regenerated by the build scripts above.

`status:` is the promotion gate: a rule is `experimental` until it has passing TP/TN fixtures, and `deploy_detections.sh` skips experimental rules. Count/cardinality logic cannot be expressed in Sigma here: the Sigma file stays `experimental` as the logic of record and is paired with a hand-written Elastic threshold rule in `rules/elastic/threshold/*.ndjson` (`test_threshold_rules.py` checks the pairing). The `description:` field renders verbatim in the Kibana alert flyout, so it holds analyst-facing text only; put rule-author rationale in a YAML comment or point at the `sigma_eval.py` docstring (`test_rule_description_hygiene.py`). This stack maps to `process.args`, never `process.command_line`.

Suricata rules have their own lane: every file in `rules/suricata/` must be listed in `configs/suricata/suricata.yaml` and vice versa, every SID is registered, and a threshold rule may only be enabled once it has a TP pcap fixture under `tests/detections/fixtures/suricata/` (`test_suricata_rules.py`, `suricata_rules_eval.py`).

### Tests mirror deployment, not just code

`tests/pipeline/` asserts on config and script text: systemd units match between repo and sandbox expectations, `$$` escaping in `ExecStart`, `.gitattributes` LF rules, gitleaks allowlist shape, Zeek image pin, ES CA fingerprint pinning. When you change anything under `configs/` or `scripts/setup/*.sh`, expect a test there to name the invariant you just touched, and update the test only when the invariant really changed. `tests/anomaly_simulation/` runs real techniques against the live stack and is manual; dashboard and detection evidence must come from real telemetry, never mock data.

## Repo workflow and record-keeping

- Branch + PR always; conventional commit prefixes (`feat:`, `fix:`, `docs:`, `chore:`, ...). A PR touching `rules/`, `configs/`, `hunts/`, the agent, the broker or `.github/` needs a code-owner review (`.github/CODEOWNERS`).
- Every merge gets a row in `README.md` (Project Status / Recent Enhancements) and a `LAST SESSION` entry in `planned_execution.md`. Bundle doc updates with the code change in the same PR; a behavior change without its doc or wiki update is incomplete.
- Review write-ups go in `findings/`, plans and handoffs in `plans/`, both named `YYYY-MM-DD-<topic>.md`. Refresh `plans/<date>-session-handoff.md` before ending a session that changed state.
- After a PR merges: close each linked issue by hand, verify it closed, update the Projects board (local session only), and only then report done.
- Trust observed output over runbooks and over a single search result. A grep that returns nothing is not evidence; confirm the pattern against a line you know exists. Mark anything you did not run as UNVERIFIED in handoffs and reports.

## Blue team analysis conventions
- Never assert an IOC is malicious without a cited source (VT, MISP, internal case).
- If log evidence is ambiguous or incomplete, say so — never guess intent or attribution.
- Map to ATT&CK technique IDs only when clearly evidenced in the provided data.
- Never invent CVEs, hashes, or timestamps — quote verbatim from the source log/report.

## Environment constraints
- **Milestone tracking lives in `planned_execution.md` and `README.md`** (repo-tracked, updated after every merge) — check those first for current per-issue status before re-deriving it from the GitHub API.
- The GitHub wiki (suburban_soc.wiki) can't be pushed to from a cloud session (git proxy blocks it; confirmed repo not found via add_repo too). A local session can push it. From cloud: clone read-only, edit Home.md locally, and send the file to the user to paste into the wiki UI.
- **Never write a closing keyword before an issue number** anywhere in a PR title, body or commit message — even negated or quoted. GitHub doesn't reliably close every issue in "Closes #X, #Y", and its parser ignores negation ("Does not close #265" closed #265). Say "leaves #N open" instead, close each issue manually after merge, and verify each one.
- **Docker depends on the session kind.** A *cloud* session has no live Docker daemon, Elasticsearch or Kibana (`docker version` reaches the client, not the socket) — Docker-dependent work there is structurally validated only, disclosed as such, never assumed to pass. **The local WSL host IS the capture host:** `zeek-host-capture.service`, `suricata.service`, `filebeat.service` and `intel-refresh.timer` run there, `/storage/PCAP/zeek_logs/` holds live Zeek output, native `/opt/zeek/bin/zeek` is 9.0.0 and `/usr/bin/suricata` is 7.0.3. Docker there comes from Docker Desktop: when the `docker-desktop` WSL distro is Stopped, `docker` drops off PATH, `zeek-host-capture.service` crash-loops and the Zeek lane silently stops writing while Suricata and Filebeat stay active. Check `/mnt/c/Windows/System32/wsl.exe -l -v` and say "start Docker Desktop" rather than "no Docker". CI's `live-fire` job has a real Docker daemon and the pinned zeek/zeek image — image-dependent tests run there (`SOC_REQUIRE_LIVE_ZEEK=1` makes a skipped live test fail instead of passing silently).
- **Repo-admin actions depend on the session kind.** A cloud session can't change branch protection, read or sync the Projects v2 board, or delete branches (no tool, no admin token) — identify what's needed and hand it to the user. A local session has `gh` authenticated as the owner (`repo`, `project`, `workflow` scopes) and can do all of it, including closing milestone objects (`gh api -X PATCH repos/voltron-1/Suburban_SOC/milestones/<n> -f state=closed`). Try the call before deferring it.
- **Cloud sandbox has no general DNS or network**, so it cannot reproduce CI's curl, Suricata or any network test; say so instead of reporting a pass.
- **Installed systemd units drift from the repo.** Before debugging a unit on the capture host, diff `/etc/systemd/system/<unit>` against `configs/systemd/<unit>` (trailing whitespace stripped). Filebeat refuses a config file not owned by root.
- **Sourcing `scripts/setup/.env` exports secrets into the shell.** Run `exec bash` afterwards and pass secrets to `docker exec` by name (`-e NAME`), never by value.
