# CLAUDE.md
Single source of truth for agent guidance; also follow `docs/CONVENTIONS.md`. Use the `sigma-rule`, `sigma-validate`, `triage` skills in `.claude/commands/`.
Suburban-SOC: OpenWrt -> Zeek/Suricata -> Filebeat -> Logstash -> Elasticsearch -> Kibana. Flask SOC AI agent triages HMAC-signed alerts into a human-approval queue; FastAPI hive-mind broker sends approved HMAC-signed blocks to routers.
## Start of session
1. Read `plans/<latest>-session-handoff.md` and the top `LAST SESSION` of `planned_execution.md`. 2. Decide session kind (cloud/local) before promising Docker, Elasticsearch, `gh` admin or wiki work. 3. Never open a PR unless asked.
## Commands
Python 3.11 only. Nothing is pip-installable; modules import as flat names (`app`, `agent`, `sigma_eval`, ...).
```bash
pip install sigma-cli==3.1.0 pysigma==1.5.0 pysigma-backend-elasticsearch==2.1.1 "pyparsing==3.3.2" pytest pyyaml requests   # pyparsing 3.3.3 breaks pysigma
pip install flask==3.1.3 requests==2.33.0 fastapi==0.121.1 uvicorn==0.34.0 pyyaml==6.0.2 asyncssh==2.18.0 httpx==0.28.1 pytest   # SOAR
pytest                                                         # whole tree
python -m pytest tests/detections/test_sigma_detections.py -q   # Sigma gate; also tests/pipeline, tests/ai_agent/test_alert_auth.py
cd scripts/hive-mind-broker && cp inventory.example.yaml inventory.yaml && python -m pytest test_app.py test_inventory.py -q
python tests/detections/test_threshold_rules.py; python tests/validate_emulation_map.py --no-color
sigma convert -t lucene -f siem_rule_ndjson -p configs/detections/suburban-soc-ecs.yml rules/sigma/<rule>.yml   # must convert, never emit process.command_line
pip install ruff==0.15.15 && ruff check .; git ls-files '*.py' | xargs mypy --ignore-missing-imports --follow-imports=silent
git ls-files '*.sh' | xargs shellcheck -S warning; yamllint -c .yamllint configs/
python scripts/setup/build_attack_coverage.py; python scripts/setup/build_kql_docs.py   # generated docs: regenerate, never hand-edit (CI --check)
```
Live stack (local only): `cp scripts/setup/.env.example scripts/setup/.env`, fill passwords, `docker compose up -d` from `scripts/setup/`. Known local failure: `tests/ai_agent/test_slo_metrics.py::MainExitCodeTests` fails if `.env` has a real `SLO_COVERAGE_MIN`.
## Detection-as-code
A Sigma rule in `rules/sigma/` is done only when all exist:
- `tests/detections/fixtures.json` (keyed by filename): exactly one `true_positive`, non-empty `true_negatives`, Sigma field names. `sigma_eval.py` tests logic only; read its docstring before using a modifier the corpus lacks.
- `docs/playbooks/IR_Sigma_Playbook.md`: `<a id="<rule stem>"></a>`, `**Rule file:**` line, matrix link; then run `playbooks/migration/split_ir_sigma_playbook.py` to regenerate `playbooks/data/`.
- `configs/detections/emulation_telemetry.map` and `coverage_checklist.md` row-for-row in sync, plus a `tests/anomaly_simulation/sim_*` script.
- Regenerated `docs/detections/attack-coverage.*` and `SIEM_KQL_Documentation.md`.

Rules: `status: experimental` until TP/TN fixtures pass (`deploy_detections.sh` skips experimental). Count/cardinality logic: keep Sigma `experimental` and pair with `rules/elastic/threshold/*.ndjson`. `description:` renders in the Kibana flyout: analyst-facing only, author rationale in a YAML comment. Use `process.args`, never `process.command_line`. Suricata: files in `rules/suricata/` and `configs/suricata/suricata.yaml` must match, every SID registered, a threshold rule needs a TP pcap under `tests/detections/fixtures/suricata/` before enabling.
## Security invariants (do not weaken)
- Human-in-the-loop by default; exclusion list checked first; autonomous isolation only with `AUTONOMOUS_ISOLATION=true`.
- Atomic create-if-absent claim in `checkpoints.py` guarantees `/approve` isolates at most once.
- `/approve` and `/pending` use HMAC credentials separate from `/alert`; unsigned/invalid requests fail closed with 401.
- Every response action stays scoped to the alerting tenant; never broadcast across tenants.
- Secrets only in `scripts/setup/.env`.
## Tests mirror deployment
`tests/pipeline/` asserts on config/script text (systemd units, `$$` escaping, `.gitattributes`, gitleaks allowlist, image pins). After changing `configs/` or `scripts/setup/*.sh`, update the named test only if the invariant really changed. Dashboard and detection evidence must come from real telemetry, never mock data.
## Workflow
- Branch + PR always, conventional commit prefixes. PRs touching `rules/`, `configs/`, `hunts/`, agent, broker or `.github/` need code-owner review; only the owner merges to `main`.
- Every merge: row in `README.md` and `LAST SESSION` entry in `planned_execution.md`, same PR as the code. Wiki updates carry a date and changelog line.
- Findings go in `findings/`, plans/handoffs in `plans/`, named `YYYY-MM-DD-<topic>.md`. Refresh `plans/<date>-session-handoff.md` before ending a session that changed state.
- After merge: close each linked issue by hand, verify closed, update Projects board (local only), then report done.
- **Never write a closing keyword before an issue number** (title, body, commit), even negated; write "leaves #N open".
- Trust observed output over runbooks; an empty grep is not evidence; mark unrun work UNVERIFIED.
## Blue team analysis
Never call an IOC malicious without a cited source (VT, MISP, internal case). Say so when evidence is ambiguous; never guess intent or attribution. Map ATT&CK only when clearly evidenced. Never invent CVEs, hashes or timestamps; quote verbatim.
## Environment
- Milestone status is in `planned_execution.md` and `README.md`; check them before the GitHub API.
- **Cloud:** no Docker, Elasticsearch, Kibana, DNS or network; disclose such work as structurally validated only. Cannot change branch protection, sync Projects, delete branches or push the wiki; hand those to the user (wiki: edit `Home.md` locally, send the file).
- **Local WSL host is the capture host** (`zeek-host-capture.service`, `suricata.service`, `filebeat.service`, `intel-refresh.timer`). If `docker` is off PATH, Docker Desktop is stopped: check `/mnt/c/Windows/System32/wsl.exe -l -v`, say "start Docker Desktop". Local has `gh` as owner (`repo`, `project`, `workflow`); try the call before deferring.
- CI `live-fire` is the only job with real Elasticsearch/Docker and is not required; `SOC_REQUIRE_LIVE_ZEEK=1` makes a skipped live test fail.
- Systemd units drift: diff `/etc/systemd/system/<unit>` against `configs/systemd/<unit>` before debugging; Filebeat refuses configs not owned by root.
- Sourcing `scripts/setup/.env` exports secrets: run `exec bash` after, pass secrets to `docker exec` by name (`-e NAME`).
