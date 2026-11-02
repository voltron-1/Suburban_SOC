# 2026-11-01 — Repository audit: code quality, engineering gaps, dual-NIST alignment

**Branch:** `Audit_20261101` (from `main` at `07c151c`). **Mode:** read-only analysis. No code, config or test was changed; this file is the only addition.
**Brief:** `repo_audit_prompt.txt` (Phases 1–4). The two follow-up "implementation" prompts in that brief were **not** executed; they need owner approval per finding.

## How this was produced, and what was not checked

- Static reading of the SOAR plane (`agent_app.py`, `agent.py`, `checkpoints.py`, broker `app.py`, `dispatcher.py`, `inventory.py`), `configs/logstash.conf`, `scripts/setup/docker-compose*.yml`, Elasticsearch roles, systemd units, shell scripts, `.github/`, both Dockerfiles and requirements files. Three parallel read-only reviewers covered config plane, Python reporting code, and CI/tests; every finding they returned that is ranked High or above was re-checked against the cited line before inclusion here.
- **Run in this cloud session (Python 3.11.18 venv):** `tests/ai_agent/test_alert_auth.py` → 70 passed; broker `test_app.py test_inventory.py test_dispatcher.py` → 92 passed; full `tests/ai_agent` with agent requirements → 585 passed, 1 skipped (90% line coverage of `scripts/setup/ai_agent`); reporting gate reproduced → 293 passed, 98.16%.
- **Reproduction (no network, no router):** AUD-01 was reproduced by calling `dispatcher.build_nft_command()` directly. Inputs and output are withheld from this public file (see the disclosure note above AUD-01).
- **UNVERIFIED (cloud session: no Docker, Elasticsearch, Kibana, Logstash, routers):** anything about live Elasticsearch role semantics (AUD-05), container gid/file-read behaviour (AUD-11), the Logstash end-to-end path in AUD-02 (static analysis of `logstash.conf` only), live branch-protection state, and the weekly-report MTTD field shape (AUD-14).

---

## Initial understanding (alignment check)

Suburban-SOC is a multi-tenant home/residential mesh-network SOC:

- **Detection plane:** OpenWrt router → tcpdump over SSH → Zeek 9.0.0 and Suricata 7.0.3 on a WSL capture host → Filebeat (mTLS) → Logstash 9.3.2 (grok, GeoIP, ECS, ATT&CK enrichment, ingest-time HMAC `/alert` trigger) → Elasticsearch 9.3.2 (per-tenant indices, RBAC, TLS) → Kibana dashboards and Detection Engine. 122 Sigma rules, 11 Suricata rule files, 5 hunts, detection-as-code gates in CI.
- **Response plane (SOAR):** Flask agent (gunicorn, 1 worker × 4 threads) does LLM triage (local Ollama by default), ATT&CK mapping, Kibana Cases, and drafts containment into a human-approval queue; FastAPI "hive-mind" broker pushes nftables blocks to tenant routers over SSH. HMAC-SHA256 with timestamp + nonce on every hop; separate approver credential; ES-backed atomic claim for at-most-once execution.
- **Stack:** Python 3.11 (Flask 3.1, FastAPI 0.138, asyncssh, requests, WeasyPrint), Ruby-in-Logstash, Bash, PowerShell (endpoint STIG), Docker Compose, systemd, GitHub Actions (pytest, ruff, mypy, shellcheck, yamllint, gitleaks, pip-audit, Trivy, CodeQL).

Overall: the response plane's authentication and idempotency engineering is unusually mature. The material gaps are at **trust boundaries the HMAC scheme does not cover** (what Logstash will sign, what an "IP" can contain), **least privilege on shared Elasticsearch identities**, and **CI not running tests that already exist**.

---

## Phase 1 — Architectural and structural mapping

### 1.1 Entry points

| Entry point | File | Auth | Notes |
|---|---|---|---|
| Beats input :5044 | `configs/logstash.conf:6-28` | mTLS, `ssl_client_authentication => "required"` | Published on all host interfaces (`docker-compose.yml:744`) — intended for LAN shippers |
| HTTP input :5514 | `configs/logstash.conf:39-43` | **None, plaintext** | Mesh-internal only; no producer found in repo |
| Agent `POST /alert` | `agent_app.py:38` | HMAC (`SOC_AGENT_HMAC_SECRET`) | Called by Logstash `http` output (`logstash.conf:1858`, plain HTTP) |
| Agent `GET /pending`, `POST /approve` | `agent_app.py:51,78` | HMAC (separate `SOC_APPROVER_HMAC_SECRET`) | ES atomic claim gates execution |
| Agent `POST /weekly-report` | `agent_app.py:111` | HMAC | Spawns daemon thread |
| Agent `/playbooks*` | `playbooks_blueprint.py` | None (read-only) | 127.0.0.1-bound |
| Broker `POST /webhook/alert`, `/webhook/dispatch`, `/approve`, `GET /pending` | `hive-mind-broker/app.py:471,528,631,621` | HMAC (`HIVE_MIND_SECRET`, one secret for all) | `/webhook/dispatch` = immediate SSH dispatch |
| Scheduled jobs | `configs/systemd/*.service|timer` | ES role per job | slo-metrics, stack-health, intel-refresh, compactors, liveness |

### 1.2 Data flow (response path)

```
Zeek/Suricata log ──Filebeat mTLS──▶ Logstash ──(if zeek.intel hit OR threat.technique.id==T1110)──▶
  Ruby block signs {severity:"critical", tenant_id, source_ip, source_mac, technique} ──HTTP──▶
Agent /alert ─▶ perceive (validate tenant/IP/MAC/technique) ─▶ dedup + suppression (ES) ─▶
  LLM triage (sanitised) ─▶ Kibana Case ─▶ exclusion list ─▶
  [AUTONOMOUS_ISOLATION && critical && (MAC || external IP)] ─▶ broker /webhook/dispatch ─▶ SSH nft
  [default] ─▶ approval queue (JSONL) ─▶ human POST /approve ─▶ ES claim ─▶ broker /webhook/dispatch ─▶ SSH nft
```

### 1.3 State management

| State | Store | Concurrency control |
|---|---|---|
| Replay nonces | In-process dict (`agent.py:257`, `app.py:55`) | `threading.Lock`; pins agent to 1 gunicorn worker (`Dockerfile:38-50`); lost on restart |
| Approval queue (agent, broker) | Append-only JSONL under `/app` | `threading.Lock` + `flock` on a never-replaced lock path (`agent.py:1114-1135`) |
| Alert checkpoints / claims | ES `agent-checkpoints-*` | `op_type=create` + `if_seq_no` optimistic concurrency (`checkpoints.py:198-257`) |
| Audit trail | ES `soc-audit-*` | Create-only role `soc_audit_appender` |
| Router inventory | `inventory.yaml` (gitignored) | Loaded once at import (`app.py:43`) |

### 1.4 Architectural anti-patterns

| # | Pattern | Evidence | Principle |
|---|---|---|---|
| A1 | **God module** — config, crypto, validation, exclusion list, LLM client, notifications, file queue, ES audit, Kibana Cases and the orchestrator in one file | `scripts/setup/ai_agent/agent.py` (1,822 lines); `dispatch_block_via_broker` 320 lines (`:464`), `act` 122 lines / cc≈29 (`:1685`), `execute_approved` 142 lines / cc≈23 (`:1508`) | SRP (SOLID-S) |
| A2 | **God script** — `slo_metrics.py` 2,093 lines; `main()` 209 lines, cc≈44 (`:1881`); config evaluated at import (`:144`, `:154-231`, `:289`) | `scripts/setup/ai_agent/slo_metrics.py` | SRP; testability (DIP) |
| A3 | **Duplicated cross-cutting code instead of `lib/`** — `ES_VERIFY = ES_CA if ES_CA else True` ×6; ntfy POST ×3; `_ntfy_header_safe` ×2; four helpers copy-pasted between the two compactors; three ES client styles (raw `requests`, `es_client.Session`, elasticsearch-py) | `agent.py:89`, `slo_metrics.py:285`, `run_hunts.py:47`, `checkpoints.py:46`, `compact_*.py`; `weekly_ciso_report.py:427-433` admits the copy | DRY; DIP |
| A4 | **Two implementations of the same security protocol** — HMAC verify/sign/nonce exists independently in agent and broker; domain constants must be kept equal by hand (`agent.py:161-163`, `app.py` `_RESPONSE_DOMAIN`) | `agent.py:313-366`, `app.py:285-338` | DRY; a shared, versioned `soc_hmac` module |
| A5 | **In-process security state constrains scaling** — nonce cache forces `--workers 1` | `Dockerfile:38-50` | Scalability; move nonce store to ES/Redis |
| A6 | **Comment-as-changelog** — 1,347 comment/docstring lines vs 555 code lines in `slo_metrics.py`; 840 vs 786 in `agent.py`; review-round history inline ("#277 round-2/3/4") | `agent.py:201-236` and passim | PEP 8 / PEP 257: comments explain *why now*, history belongs in git/`findings/` |
| A7 | **Broker lane duplication** — broker has its own draft/approve queue (`/webhook/alert` + `/approve`) parallel to the agent's, but the agent only uses `/webhook/dispatch`; the legacy lane has weaker controls (AUD-04, AUD-09) | `app.py:471-526`, `631-705` | YAGNI; reduce attack surface (CM-7) |

No circular imports were found (`agent_app` → `agent` → `checkpoints`/`retry`; broker `app` → `dispatcher`/`inventory`).

---

## Phase 2 — Evidence-based engineering gap analysis with dual-NIST mapping

Severity: **C** Critical · **H** High · **M** Medium · **L** Low. CSF = NIST CSF 2.0 subcategory; 800-53 = SP 800-53 Rev. 5 control.

### 2.1 Defensive design and compliance

> **Disclosure note:** this repository is public. AUD-01 and AUD-02 are described here at the level of the control gap only. The reproduction steps, test inputs and full attack chain are withheld until the fixes merge; the owner holds them in the private report.

#### AUD-01 (C) — Address validation in the broker dispatch path does not guarantee a value that is safe to place in the router command

- **Evidence:**
  - `scripts/hive-mind-broker/dispatcher.py:92-100`: `validate_ip()` checks that the value parses as an IP address. It does not check that the accepted string is limited to the characters an address needs.
  - `dispatcher.py:165-167` and `:170-176`: `build_nft_command()` and `build_nft_verify_command()` place the caller's original string, not a canonical form of the parsed address, into a command that `asyncssh` `conn.run()` (`:385`) runs in the router user's shell (root by default, `:358`). The element is not quoted.
  - `agent.py:396-401`: the agent-side `is_valid_ip()` uses the same parse-only check, and `_is_private_ip()` (`:404-433`) feeds the autonomous-isolation decision (`:1741-1742`).
  - No existing test exercises unusual-but-parseable address forms on either service.
- **Verification:** reproduced in this session against `build_nft_command()` directly (no network, no router). Details withheld from this public file.
- **Impact:** a value that passes validation can change the command the router executes. In the default mode one human approval stands between the input and the router; with `AUTONOMOUS_ISOLATION=true` there may be none. Any holder of `HIVE_MIND_SECRET` can also reach the dispatch path directly.
- **Corrective action:**
  - Restrict accepted addresses to plain IPv4/IPv6 forms and reject anything else.
  - Build commands from the canonical `str()` of the parsed address, never the raw input, and `shlex.quote()` the element.
  - Apply the same rule in `agent.is_valid_ip()` and `_is_private_ip()`; refuse rather than fall back.
  - Add negative tests on both services.
  - Runtime contract preserved: every plain IPv4/IPv6 input produces byte-identical commands.
- **CSF 2.0:** PR.DS-10, PR.PS-06, PR.IR-01, RS.MI-01. **800-53:** SI-10, SI-10(5) (restrict inputs to trusted sources and approved formats), SI-7, SC-7, CM-7.

#### AUD-02 (C with AUD-01 / H alone) — The ingest-time `/alert` trigger relies on fields whose origin Logstash does not establish

- **Evidence:**
  - `configs/logstash.conf:1728`: the trigger condition and the signed body (`:1745-1751`) use event fields as received. Logstash does not record or check which input or sensor produced them.
  - `:39-43`: a plaintext, unauthenticated HTTP input on `:5514`, reachable on the internal `soc-mesh-net` network. No producer for it exists in the repo.
  - `configs/network/filebeat.yml:136` and `mint_endpoint_cert.sh:37-38`: tenant is asserted by the shipper, not derived from its certificate.
  - `:1690` states that only validated IP/MAC go in the body; `source_ip` is not validated before signing.
- **Impact:** the agent's HMAC authenticates Logstash as the last hop, not the origin of the data. The tenant-scoping invariant in CLAUDE.md ("every response action stays scoped to the alerting tenant") therefore depends on every upstream sender being trustworthy. Static analysis only; the end-to-end path was not run (UNVERIFIED).
- **Corrective action:**
  1. Remove the `:5514` input, or put it behind TLS and authentication.
  2. Gate the trigger on a provenance marker that Logstash sets itself for sensor-origin events (e.g. `[@metadata][origin]`), never on fields carried in the event body.
  3. Strip enrichment-owned fields (`threat.*`, `note`, `event.dataset`) from shipper input before enrichment.
  4. Derive tenant from the client-cert subject (`ssl_peer_metadata`).
  5. Validate `source_ip` in the Ruby block before signing.
- **CSF 2.0:** PR.AA-03, PR.AA-05, PR.DS-02, DE.AE-02. **800-53:** IA-3, IA-9, AC-4, AC-3, SI-10, SC-8.

#### AUD-03 (H) — `logstash_writer` can delete every tenant's telemetry; the agent reuses that identity

- **Evidence:** `configs/elasticsearch/roles/logstash_writer.json` grants `["create_index","create","write","manage","auto_configure"]` on `logstash-*` and `soar-actions-*`. The `manage` privilege includes deleting indices; `write` includes deleting documents. Also `docker-compose.yml:789-790`: `ES_USER=logstash_internal`, `ES_PASS=${LOGSTASH_PASSWORD}` for the **ai-agent**, which the comment at `:786` calls temporary ("WS3.2 will split").
- **Impact:** compromising either service allows cross-tenant evidence destruction and rewriting of the SOAR action history used for MTTR/SLO.
- **Corrective action:**
  - Restrict `logstash_writer` on data streams to `create_doc`/`create`, `create_index` and `auto_configure`.
  - Give the agent its own `soar_actions_appender` role (create-only on `soar-actions-*`).
  - Contract preserved: both services only ever index new documents.
- **CSF 2.0:** PR.AA-05, PR.DS-01, PR.PS-04. **800-53:** AC-6, AC-6(10), AU-9, AC-5.

#### AUD-04 (H) — One shared secret on the broker: `/approve` cannot prove a human approved

- **Evidence:** the broker's `/approve` and `/webhook/dispatch` are both gated on `HIVE_MIND_SECRET` (`app.py:47`). The ai-agent container holds that secret. The limitation is documented in the code itself (`app.py:639-646`, #273): "A compromised agent ... can call /approve ... Do not read that label as cryptographic proof of a human-of-record."
- **Corrective action (pick one):**
  - **(Preferred)** Retire the broker's own draft/approve lane (`/webhook/alert`, `/pending`, `/approve`). The agent's approval flow already carries the human gate, and nothing in-repo calls the broker lane (A7).
  - Otherwise, give `/approve` and `/pending` a second credential the agent never holds, as #246 did for the agent.
- **CSF 2.0:** PR.AA-05, GV.RR-04 (separation of duties in roles). **800-53:** AC-5, IA-2, AC-3, AU-10 (non-repudiation).

#### AUD-05 (H, UNVERIFIED live) — `soc_admin`'s `-` "exclusion" patterns are probably not exclusions

- **Evidence:** `configs/elasticsearch/roles/soc_admin.json:4` grants `"soc-*"` together with `"-soc-audit-*"` and similar entries, with `["all"]`. Role `names` support wildcards and `/regex/`. The leading `-` is search-API syntax and, by the auditor's understanding, does not exclude anything in a role. The repo's own test says this was never confirmed: `tests/setup/test_soc_admin_role_scope.py:38-40`.
- **Impact:** if the patterns don't exclude, a `soc_admin` holder can delete the append-only audit trail.
- **Corrective action:**
  - Use a Lucene-regex form, e.g. `/soc-.*&~(soc-audit-.*|soc-health|soc-slo-metrics|soc-agent-health-.*)/`.
  - Verify with `GET _security/user/_has_privileges` as a `soc_admin` test user.
  - Make `apply_roles.sh` fail on a non-2xx PUT (AUD-21).
- **CSF 2.0:** PR.AA-05, PR.PS-04. **800-53:** AC-6, AU-9, AU-9(4).

#### AUD-06 (H) — No security audit logging on Elasticsearch or Kibana

- **Evidence:** `grep -rn "security.audit"` over `configs/` and `scripts/` finds no `xpack.security.audit.*` setting.
- **Impact:** deletions, privilege use and authentication failures against the evidence store (the targets of AUD-03 and AUD-05) leave no record on the server side. The SOC cannot detect tampering with itself.
- **Corrective action:**
  - Enable `xpack.security.audit.enabled=true` and ship the audit log to a separate, append-only index or a host file.
  - If the licence tier does not allow this, record it in `governance/` as an accepted risk with a compensating control, e.g. snapshot immutability.
- **CSF 2.0:** PR.PS-04, DE.CM-09, DE.CM-03. **800-53:** AU-2, AU-3, AU-12, AU-6.

#### AUD-07 (H) — Default ntfy topic is public and guessable, and the payload carries unmasked IOCs and tenant names

- **Evidence:**
  - `docker-compose.yml:742`: `NTFY_TOPIC=${NTFY_TOPIC:-subsoc-alerts}`. The `:-` operator also substitutes when the variable is empty.
  - `.env.example:132` ships `NTFY_TOPIC=`, which its header documents as "disabled".
  - `logstash.conf:1832-1835` posts `%{[threat][indicator][value]}` and `tenant=%{[tenant][id]}` to `https://ntfy.sh/…`.
- **Corrective action:**
  - Treat an empty `NTFY_TOPIC` as disabled in Logstash: wrap the output in a conditional and drop the fallback.
  - Mask the indicator value the same way `notify_source_ip` is masked (`:452-463`).
- **CSF 2.0:** PR.DS-02, PR.DS-10. **800-53:** AC-4, SC-8, SI-12, PT-2.

#### AUD-08 (H) — Unbounded request bodies are read into memory before authentication

- **Evidence:** `agent_app.py:41` (`request.get_data()`) and `agent.py:383` read the whole body before the HMAC check. There is no `MAX_CONTENT_LENGTH` anywhere (grep). The broker does the same in `app.py:318` (`await request.body()`).
- **Impact:** after authentication, the full payload is stored as checkpoint context (`agent.py:1480`), and `raw_log` goes to the LLM uncapped (`:1680`). With 1 worker × 4 threads (`Dockerfile:48`), a few large or slow requests also starve `/approve`.
- **Corrective action:**
  - Set `app.config["MAX_CONTENT_LENGTH"]` (e.g. 256 KiB), which returns 413 before the body is read.
  - Add a Starlette body-size middleware on the broker.
  - Cap `raw_log` before the LLM call.
  - Contract preserved: Logstash bodies are about 200 bytes.
- **CSF 2.0:** PR.IR-03 (resilience), PR.DS-10. **800-53:** SC-5, SI-10.

#### AUD-09 (M) — Broker `/approve` is check-then-act with no claim (TOCTOU)

- **Evidence:** `app.py:663-694` reads the queue, checks for a pending row, then `await dispatch_block_to_all(...)` (`:695`) and appends `approved` afterwards. Two concurrent requests for the same id both dispatch.
- **Impact:** `nft add element` is idempotent (`dispatcher.py:131-137`), so router state is unaffected. The audit trail gets two `approved` rows, and the "at most once" guarantee in CLAUDE.md is false for this lane.
- **Corrective action:** retiring the lane closes this (AUD-04). Otherwise, reuse the agent's create-if-absent claim pattern.
- **CSF 2.0:** PR.PS-06. **800-53:** SI-7, AU-10.

#### AUD-10 (M) — `severity` is unvalidated at the trust boundary

- **Evidence:** `agent.py:1656` `severity = payload.get("severity", "medium")` accepts any type and length. `.upper()` at `:1697` and `:1801` raises for a non-string, and this happens after the PERCEIVING checkpoint is written.
- **Impact:** the request returns 500 halfway through, and the value flows into the dedup key, Kibana tags and case titles.
- **Corrective action:** allowlist `{"low","medium","high","critical"}` in `perceive()` (same pattern as `_TECHNIQUE_RE`). Unknown values map to `"medium"` and an audit marker is written.
- **CSF 2.0:** PR.DS-10. **800-53:** SI-10, SI-11.

#### AUD-11 (M, partly UNVERIFIED) — CA private key in a shared volume; one CA for every identity; no revocation

- **Evidence:**
  - `docker-compose.yml:162,203-205`: `ca.zip` and `ca/ca.key` stay in the `certs` volume, which is mounted read-write into ES, Kibana and Logstash (`:548,595,746`).
  - Transport TLS `verification_mode=certificate` (`:538`) checks the CA only, not the host name.
  - Endpoint certs last 365 days with no CRL (`mint_endpoint_cert.sh:64`).
  - `mint_endpoint_cert.sh:27` claims the key "never leaves the Elasticsearch container". That holds for the container but not for the shared volume.
- **Corrective action:**
  - Move the CA key to a setup-only volume.
  - Use a separate intermediate CA for endpoint client certs.
  - Change transport verification to `full`.
  - Document revocation (rotate the intermediate CA).
- **CSF 2.0:** PR.AA-01, PR.DS-01. **800-53:** SC-12, SC-17, IA-5(2).

#### AUD-12 (M) — Delete-capable compactor units do not pin the CA

- **Evidence:** `configs/systemd/checkpoints-compact.service:94` and `threat-intel-compact.service:81` copy `ca.crt` out of the container without `verify_ca_fingerprint.sh`. `slo-metrics.service:185` and `stack-health.service:111` do pin it.
- **Corrective action:** add the same `ExecStartPre` fingerprint check, and extend the `tests/pipeline` parity test to every unit that copies the CA.
- **CSF 2.0:** PR.DS-02. **800-53:** SC-8, SC-17, SI-7.

#### AUD-13 (M) — Container and capture-host hardening gaps

- **Evidence:**
  - No `cap_drop`, `security_opt`, `read_only`, `pids_limit` or `logging:` in either compose file (grep).
  - `host_capture.sh:74` runs the Zeek container, which parses hostile traffic, without `--cap-drop ALL`, `--read-only`, `--network none` or `--security-opt no-new-privileges`.
  - The broker mounts the operator's whole `~/.ssh` by default (`docker-compose.yml:901`).
  - No `.dockerignore` exists, so `COPY . .` (`hive-mind-broker/Dockerfile:11`) bakes a host's real `inventory.yaml` into the image layer. This contradicts `Dockerfile:20-21`.
  - Host scripts default to the `elastic` superuser (`lib/es_common.sh:53`).
- **Corrective action:**
  - Add `cap_drop: [ALL]`, `security_opt: [no-new-privileges:true]` and `read_only` with `tmpfs` to the agent and broker.
  - Add `json-file` log rotation.
  - Mount a dedicated `HIVE_MIND_SSH_DIR` holding only the router key and `known_hosts`.
  - Add `.dockerignore` files (excluding `inventory.yaml`, `test_*.py`, `.env`).
  - Require an explicit `ES_USER` in host scripts.
- **CSF 2.0:** PR.PS-01, PR.AA-05. **800-53:** CM-6, CM-7, AC-6, SC-39.

#### AUD-14 (H) — Executive report replaces real data with invented numbers when ES fails

- **Evidence:** `weekly_ciso_report.py:114-124` catches any exception and returns `{"total_alerts": 342, "average_mttd_minutes": 18.5, ..., "demo_mode": True}`. The ntfy summary (`:450-455`) does not say it is demo data. Separately, MTTD is computed differently here (`:133-145`, `kibana.alert.start - @timestamp`, nested-dict read) than in `slo_metrics.py:444,458-459` (`kibana.alert.original_time`, dotted keys). The weekly figure is probably near zero or empty (UNVERIFIED against a live index).
- **Impact:** the board-level report can carry fabricated metrics. That breaks CLAUDE.md "evidence must come from real telemetry, never mock data" and is a governance-reporting integrity failure.
- **Corrective action:**
  - Fail the pipeline, or send an explicit "REPORT UNAVAILABLE" notice, instead of demo data. Keep demo mode only behind an explicit `--demo` flag.
  - Compute MTTD in one shared function that both scripts import.
- **CSF 2.0:** GV.OV-03 (performance evaluated), GV.RM, ID.IM-01. **800-53:** SI-11, CA-7, PM-6, AU-6.

#### AUD-15 (M) — SLO and notification paths that fail silently

- **Evidence:**
  - `slo_metrics.py:520-521` never checks the status of a Kibana `cases/_find` call, so a 401/403 error body reads as `total=0`, which reports a healthy 0% false-positive rate. It also queries only the default space, while cases live in `/s/{tenant}` (`agent.py:1254-1255`).
  - `slo_metrics.py:2076-2081`: `except Exception: pass` around the only breach push.
  - `agent.py:1237-1245`: `log_soar_action` ignores bulk `errors`.
  - `run_hunts.py:158-161` reports "indexed N" without checking the response.
  - `agent.py:1764`: Discord says "Device Automatically Quarantined" even when `ok` is False (embed text at `:1088-1093`).
- **Corrective action:**
  - Call `raise_for_status()` plus check bulk `errors` on every write.
  - Treat an HTTP error as `MetricUnavailable`, not 0.
  - Log, and count, every failed notification.
  - Branch the Discord embed on `ok`.
- **CSF 2.0:** DE.CM-09, RS.CO-02/03. **800-53:** SI-4, AU-5 (response to audit logging failures), SI-11, IR-6.

#### AUD-16 (M) — LLM boundary: sanitiser coverage and prompt-injection exposure to the approver

- **Evidence:**
  - **The sanitiser covers IPv4 only.** `agent.py:888` `_IP_RE` misses IPv6 addresses and usernames.
  - **Field names are over-redacted.** `_HOST_RE` (`:894`) also redacts names such as `source.ip`.
  - **The hosted-LLM check is a substring match.** `_is_hosted_endpoint()` (`:913-914`) treats `https://ollama-proxy.example.com` as local. `weekly_ciso_report.py:176-177` has a second, divergent copy.
  - **The LLM output reaches the approver unfenced.** It goes into the case, the queue row, ntfy and Discord (`:1284,1787,1802`), and `raw_log` reaches the LLM with no delimiter or size cap (`:992-1003`).
- **Mitigating:** the LLM output never decides an action, which is good design.
- **Corrective action:**
  - Parse the URL and compare its hostname against an allowlist.
  - Add IPv6 and username patterns.
  - Wrap the log in explicit delimiters with a size cap.
  - Label AI text in approval views as "untrusted model output".
- **CSF 2.0:** PR.DS-10, PR.DS-02. **800-53:** AC-4, SI-10, SI-15 (information output filtering), SA-9 (external system services) for the hosted endpoint.

#### AUD-17 (L) — Internal hops are plain HTTP; secret checks fail open on the sending side

- **Evidence:**
  - Logstash → agent `http://soc_ai_agent:5000/alert` (`logstash.conf:1858`); agent → broker `http://hive_mind_broker:8000` (`agent.py:139`).
  - Logstash signs with an empty key if the secret is unset (`logstash.conf:1732`). The receiver fails closed, so the cost is noise.
- **Corrective action:**
  - Use TLS on the mesh with the stack CA.
  - Add a `${SOC_AGENT_HMAC_SECRET:?}` guard in compose for Logstash.
- **CSF 2.0:** PR.DS-02. **800-53:** SC-8, SC-8(1), IA-5.

#### AUD-18 (L) — Secrets on process command lines and in a bash `-c` string at Compose parse time

- **Evidence:**
  - `docker-compose.yml:112-114,136-138` (single-`$` `ELASTIC_PASSWORD` inside `bash -c`, running as `user: "0"`). This is acknowledged at `:47-68`.
  - `provision_tenant.sh:89,97`: the password goes in `-d` and is printed to stdout.
  - `provision_tenant.sh:57,64,83,89` and `erase_tenant.sh:193,225`: `|| true` on writes, so erasure proceeds even if the audit record was not written.
- **Corrective action:**
  - Pass secrets via `$$VAR` and container environment variables.
  - Use `--data @-` from stdin.
  - Make the erasure audit write mandatory (fail closed).
- **CSF 2.0:** PR.AA-01, PR.PS-04. **800-53:** IA-5(7), AU-5, AU-9.

### 2.2 Code quality and maintenance (SOLID / PEP 8 / PEP 257)

| ID | Sev | Evidence | Fix | Standard |
|---|---|---|---|---|
| AUD-19 | M | God modules: A1, A2 above | Split `agent.py` into `auth.py` (HMAC/nonce), `validation.py`, `notify.py`, `cases.py`, `queue.py`, `broker_client.py`, `agent_core.py`. Keep `agent.py` re-exporting the current names so imports (`agent_app.py:13-17`, the tests) do not change | SRP, OCP |
| AUD-20 | M | Duplication: A3, A4 | `lib/soc_http.py` (ES session, CA verify, ntfy), `lib/soc_hmac.py` shared by agent and broker (vendored into both images at build time) | DRY, DIP |
| AUD-21 | M | `apply_roles.sh:108-110` and compose `roles` service (`:701-706`) print the HTTP code and continue on 4xx | `[[ $code == 2* ]] \|\| exit 1` | Fail-fast; Google Shell Style Guide |
| AUD-22 | L | Comment-as-changelog (A6); stale docstring `agent.py:1114-1118` (references `approve_action()` TOCTOU path that no longer calls it) | Move history to `findings/`; keep comments to the current invariant | PEP 257 |
| AUD-23 | L | Missing type hints/docstrings: ~27 `metric_*` in `slo_metrics.py`; `analyze_alert_with_ai`, `send_soc_alert`, `create_case`, `write_audit` in `agent.py`; `retry.py` | Annotate; enable `--check-untyped-defs` (AUD-29) | PEP 484, PEP 257 |
| AUD-24 | L | `retry.py:18` `e.response.status_code` raises `AttributeError` when `response is None`; `@retry` on `think()` (`agent.py:1678`) never fires (callees catch everything) and would duplicate Kibana cases if it did | Guard None; retry only `analyze_alert_with_ai`, not `create_case` | Least surprise; idempotency |
| AUD-25 | L | `playbooks_blueprint.py:83-84` `pb["id"]` KeyError contradicts the "malformed record must not take down the dashboard" comment at `:57`; `/context.json` (`:142`) has no consumer | `.get()` + skip; remove or wire the route | Robustness principle; YAGNI |
| AUD-26 | L | `build_attack_coverage.py:316-317` regex-harvests ATT&CK tags over the whole YAML (comments count); reads `logstash.conf` at import (`:36`) | Parse with `yaml.safe_load`, read `tags:` only | Correctness |

### 2.3 Testing and reliability

| ID | Sev | Evidence | Fix | Mapping |
|---|---|---|---|---|
| AUD-27 | **H** | **~207 existing tests never run in CI.** `soar-tests.yml` runs 4 agent test files and broker `test_app.py test_inventory.py` only. Not run: `test_agent.py`, `test_audit_write_health.py`, `test_checkpoints_suppression.py`, `test_compact_agent_approval_queue.py`, `test_compact_threat_intel.py`, `test_manage_stuck_claims.py`, `test_notify_masking.py`, `test_playbooks_blueprint.py` (~175 tests), broker `test_dispatcher.py` (25) and `test_compact_broker_approval_queue.py` (7). `dispatcher.py` coverage from gated suites: **39%** (91% with `test_dispatcher.py`). Also ungated: `test_rule_description_hygiene.py`, `test_coverage_checklist_sync.py`, `test_validate_emulation_map.py` (CLAUDE.md calls these gates). All pass today when run by hand. | Replace per-file lists with `pytest tests/ai_agent` and `pytest scripts/hive-mind-broker`; run `pytest tests/` in Detections CI | CSF ID.IM-02, PR.PS-06 · 800-53 SA-11, SA-11(1), CM-3(2) |
| AUD-28 | **H** | **Broker tested on a different stack than it ships.** `requirements.txt:4,7,10` `fastapi==0.138.0`, `starlette==1.3.1`, `asyncssh==2.24.0`; `soar-tests.yml:34` installs `fastapi==0.121.1 … asyncssh==2.18.0` (resolves starlette 0.49.3, a different major). CLAUDE.md repeats the stale pins. | CI installs `-r scripts/hive-mind-broker/requirements.txt` + `-r scripts/setup/ai_agent/requirements.txt`; delete hand-pinned lines | CSF PR.PS-01, GV.SC-07 · 800-53 CM-2, SA-11, SR-3 |
| AUD-29 | M | Coverage gate (`reporting-coverage.yml:56-58`) excludes every response-plane module (`agent`, `agent_app`, `checkpoints`, `dispatcher`, broker `app`); floor 70% vs measured 98% | Add a second gate on the SOAR modules at measured-minus-2%; per-module floors via `coverage report --fail-under` per file | 800-53 SA-11, SA-15(7) |
| AUD-30 | M | mypy lenient: `lint.yml:58` `--ignore-missing-imports --follow-imports=silent`, no `[tool.mypy]`; `--check-untyped-defs` reveals 108 errors in 25 files | Add `[tool.mypy] check_untyped_defs = true` with a per-module ratchet | PEP 484; 800-53 SA-11(1) |
| AUD-31 | M | Broker `_read_queue()` (`app.py:277-282`) has no per-line `JSONDecodeError` handling and `a["id"]` KeyError — one bad line 500s `/pending` and `/approve` (agent's equivalent at `agent.py:1153-1170` is tolerant) | Mirror the agent's tolerant reader | 800-53 SI-11; robustness |
| AUD-32 | L | Known non-hermetic test: `test_slo_metrics.py::MainExitCodeTests` reads the real `scripts/setup/.env` (CLAUDE.md) — root cause is import-time config (A2) | Load config in `main()`; tests inject env | Test isolation |

### 2.4 Performance and scalability

| ID | Sev | Evidence | Fix |
|---|---|---|---|
| AUD-33 | M | `/alert` performs ~10 sequential HTTP calls with no connection pooling (`requests.post` at `agent.py:540,1007,1068,1100,1237,1265,1349,1383`), LLM up to 30 s, broker up to 25 s, on 4 threads total | One pooled `requests.Session`; return 202 after the checkpoint and run think/act on a bounded work queue; separate thread pool for `/approve` |
| AUD-34 | M | Weekly report `size: 10000` with `total_alerts = len(hits)` (`weekly_ciso_report.py:104,126`) silently caps; `metric_orphaned_claims` `size: 200` (`slo_metrics.py:867,934`); `metric_mttd` averages only the latest 500 (`:443`) | `track_total_hits` + aggregations (`value_count`, `avg` over a scripted/runtime field), or PIT + `search_after` |
| AUD-35 | L | `_read_queue()` loads the whole JSONL on every `/pending` (agent `:1153`, broker `:277`, read twice per call in broker `:625-627,663-665`); mitigated by compaction | Single pass; or move queue to ES like checkpoints |
| AUD-36 | L | Nonce prune is O(n) under lock per request (`agent.py:296-299`, `app.py:330-332`); cache lost on restart re-opens the 300 s replay window | Store nonces in ES with `op_type=create` + TTL (also removes the 1-worker pin, A5) |
| AUD-37 | L | `suricata_threshold_baseline.py:151` keeps every timestamp per key in memory | Bucketed counts / streaming windows |

### 2.5 Supply chain and CI hygiene

| ID | Sev | Evidence | Fix | Mapping |
|---|---|---|---|---|
| AUD-38 | M | No hash pinning / lockfile; transitive deps float; `FROM python:3.11-slim` not digest-pinned (both Dockerfiles); Elastic images tag-only (`docker-compose.yml:37,511,565,617,710`); apt packages unversioned | `pip-compile --generate-hashes` → `requirements.lock`, `pip install --require-hashes`; `FROM python:3.11-slim@sha256:…`; Dependabot `docker` ecosystem to bump digests | CSF GV.SC-07, ID.RA-01 · 800-53 SR-3, SR-4, CM-2, SI-7 |
| AUD-39 | M | `lint.yml:24` downloads shellcheck from the moving `stable` URL with no checksum, then `sudo mv`; mypy, yamllint, pip-audit, pytest unpinned | Pin version + `sha256sum -c`; pin all CI tools | 800-53 SR-3, SA-10 |
| AUD-40 | M | No `permissions:` in `reporting-coverage.yml`, `secret-scan.yml`, `security-scan.yml`; checkout keeps `persist-credentials: true` | `permissions: contents: read` at workflow top; `persist-credentials: false` | CSF PR.AA-05 · 800-53 AC-6 |
| AUD-41 | M | Trivy fails only on `CRITICAL` with `ignore-unfixed` (`security-scan.yml:53,55,85,87`); Elasticsearch/Kibana/Logstash images never scanned; IaC scan path misses the broker Dockerfile (`:103`); stale `--ignore-vuln PYSEC-2026-161` whose reason no longer holds (`:29-32`) | Fail on `HIGH,CRITICAL` with a time-boxed `.trivyignore`; add Elastic images to the matrix; `scan-ref: .`; drop the stale exception | CSF ID.RA-01 · 800-53 RA-5, SI-2 |
| AUD-42 | M | Branch protection: `lint.yml` "suricata -T" and "docker compose config" not in `REQUIRED_CHECKS` (`setup_branch_protection.sh:61-76`); code-owner review off by default (`:52`, `REQUIRE_REVIEW:-0`); CODEOWNERS omits `.gitleaks.toml`, `docker-compose*.yml`, `scripts/setup/*.sh`, `scripts/setup/lib/`, `tests/`, `pyproject.toml` | Add both checks; extend CODEOWNERS; decide (owner) whether to enable code-owner review | CSF GV.RR, PR.PS-06 · 800-53 CM-3, CM-5, AC-5 |
| AUD-43 | L | No `dependabot.yml`; CodeQL Python only with default suite (`codeql.yml:46,77`); no `actions` language; no `timeout-minutes`/`concurrency`; ruff default rules only; shellcheck at `-S warning` hides 67 info/style items; 28 `.ps1` files unlinted | Add `dependabot.yml` (pip, docker, github-actions); CodeQL `security-extended` + `actions`; ruff `select = ["E","F","B","S","UP"]` with per-file ignores for tests; PSScriptAnalyzer job | 800-53 SA-11, RA-5 |

---

## Phase 3 — Technical-debt themes

| Theme | Findings | Root cause | Business impact |
|---|---|---|---|
| **T1. Trust is checked at the edge of each service, not end-to-end** | AUD-01, 02, 04, 07, 10, 17 | Each hop was hardened (and well) in isolation by issue-sized PRs; nobody owns the question "which upstream party controls this byte?". HMAC was treated as provenance when it only proves the last signer. Validation leaned on `ipaddress` without checking what it accepts. | Authentication on each hop does not add up to end-to-end assurance of what reaches the routers. This is the largest liability and compliance (PR.AA, SI-10) exposure in the repo. |
| **T2. Shared, over-privileged identities** | AUD-03, 04, 05, 11, 13 | Bootstrap-era shortcuts ("WS3.2 will split", one CA, one broker secret) were documented as temporary and never revisited; there is no live check that role JSON means what it says. | Evidence integrity of the SOC itself can't be asserted to an auditor (AU-9, AC-6); one compromised container ≈ all tenants. Blocks any SOC 2 / CSF "Protect" attestation. |
| **T3. CI proves less than the team believes** | AUD-27, 28, 29, 30, 41, 42 | Workflows list test files by name; new tests were added to `tests/` but not to YAML. Hand-written dependency pins in CI drifted from `requirements.txt` after Dependabot bumps. Gates were set at introduction and never ratcheted. | Green CI is currently not evidence that the dispatcher's double-dispatch safety, IOC masking, or suppression logic works — regressions there would merge. False confidence slows incident response when something breaks "that was tested". |
| **T4. Silent failure in the self-monitoring and reporting plane** | AUD-14, 15, 31, 34 | Broad `except Exception` + "never crash the reporter" applied without a rule that failure must still be *visible*; HTTP status not checked on writes; demo fallback left in a production path. | The SOC can report "healthy" or fabricated numbers to leadership while blind — the exact failure the M26 milestone exists to prevent. Undermines governance reporting (GV.OV) and erodes stakeholder trust in every metric. |
| **T5. Monolithic modules and duplicated cross-cutting code** | A1–A7, AUD-19–26, 33 | Rapid issue-driven growth; each fix appended to the nearest file with its review history inline. No shared library for HTTP/ES/HMAC beyond two small `lib/` modules. | Each security fix must be applied in 2–6 places (e.g. `_is_hosted_endpoint` already diverged); onboarding and review cost rises; a 1,822-line module with 50% comments is slow to audit, which is itself a security cost. |
| **T6. Supply-chain reproducibility** | AUD-38, 39, 40, 43 | Direct pins only; images by tag; CI tools fetched live. | Builds are not reproducible bit-for-bit; a compromised upstream tag or tool lands in a required check without review (SR-3/SR-4). |

---

## Phase 4 — Prioritised remediation roadmap

Each item is sized to one branch and one PR. Per the brief's follow-up protocol, each should get its own GitHub issue first; the branch name then follows `remediation/issue-<n>-nist`. **No issue numbers exist yet** — the owner creates them.

### Critical — fix immediately

| # | Item | Acceptance criteria (measurable) | NIST targets |
|---|---|---|---|
| C1 | **Harden address validation and command construction in the dispatch path (AUD-01)**: `dispatcher.validate_ip`/`build_nft_command`/`build_nft_verify_command`, `agent.is_valid_ip`/`_is_private_ip` | (1) only plain IPv4/IPv6 forms are accepted on both services; (2) commands are built from the canonical parsed address and `shlex.quote`d; (3) new negative tests (input set in the private report) fail on the current code and pass after; (4) every existing broker/agent test passes unchanged; (5) `test_dispatcher.py` runs in CI (see H1) | SI-10, SI-10(5), CM-7 · PR.DS-10, PR.PS-06 |
| C2 | **Establish origin before the `/alert` trigger signs (AUD-02)** | (1) `:5514` input removed, or TLS + auth with a named producer; (2) the `/alert` trigger condition references only fields set by Logstash itself for sensor-origin events; a test in `tests/pipeline/` asserts no shipper-settable field gates it; (3) `source_ip` is validated in the Ruby block before signing; (4) tenant for endpoint-origin events is derived from the client-cert subject, with a test; (5) live check (local session): an event POSTed with `event.dataset: zeek.intel` from a non-sensor source produces **no** `/alert` call | IA-3, IA-9, AC-4, SI-10 · PR.AA-03, PR.AA-05 |

### High — next sprint

| # | Item | Acceptance criteria | NIST targets |
|---|---|---|---|
| H1 | **Run every existing test in CI (AUD-27) and test what ships (AUD-28)** | `soar-tests.yml` invokes `pytest tests/ai_agent` and `pytest scripts/hive-mind-broker` (directories, not file lists) and installs from the two `requirements.txt` files; Detections CI runs `pytest tests/detections tests/*.py`; CI test count rises by ≥200; CLAUDE.md pins updated | SA-11, CM-2 · ID.IM-02, PR.PS-06 |
| H2 | **Least-privilege ES identities (AUD-03, AUD-05)** | `logstash_writer` has no `manage`/`write`/`delete*`; agent uses a new create-only role; `soc_admin` uses a regex exclusion; a `_has_privileges` check (script + test) proves `soc_admin` and `logstash_writer` **cannot** `delete_index` on `soc-audit-*` / `logstash-*`; `apply_roles.sh` exits non-zero on any non-2xx | AC-6, AC-6(10), AU-9 · PR.AA-05 |
| H3 | **Separate the human approval credential on the broker, or retire the broker lane (AUD-04, AUD-09)** | Either `/webhook/alert`, `/pending`, `/approve` are removed with their tests updated and docs/SOP-022 amended, **or** `/approve` + `/pending` verify a second secret absent from the agent container and a claim prevents double execution (concurrency test with 2 parallel requests → exactly 1 dispatch) | AC-5, IA-2, AU-10 · PR.AA-05 |
| H4 | **Turn on Elasticsearch/Kibana security audit logging (AUD-06)** | `xpack.security.audit.enabled=true` in compose with an event filter; audit events visible for a test `DELETE`; or a signed risk acceptance in `governance/` naming the licence limit and compensating control | AU-2, AU-3, AU-12 · PR.PS-04, DE.CM-09 |
| H5 | **No fabricated or silently-zero metrics (AUD-14, AUD-15)** | Demo fallback reachable only via an explicit flag; ES failure → non-zero exit + "REPORT UNAVAILABLE" notice; one shared MTTD function used by both scripts; every ES/Kibana write and read checks status and bulk `errors`; FP metric iterates tenant spaces; tests for 401 → `MetricUnavailable` | SI-11, AU-5, CA-7 · GV.OV-03, DE.CM-09 |
| H6 | **Bound inputs and egress (AUD-07, AUD-08, AUD-10)** | Empty `NTFY_TOPIC` disables the Logstash push (test asserts no `subsoc-alerts` fallback in compose or conf); `MAX_CONTENT_LENGTH` set (test: 1 MiB body → 413 before HMAC); broker body limit middleware; `severity` allowlisted (test: list/int/oversized → treated as `medium`, no 500) | SC-5, SI-10, AC-4 · PR.DS-02, PR.DS-10 |

### Medium / Low — backlog

1. **Hardening batch:** AUD-11 (CA key off the shared volume, intermediate CA for endpoints, transport `full`), AUD-12 (CA pin on compactors), AUD-13 (`cap_drop`, `no-new-privileges`, `.dockerignore`, dedicated SSH dir, no `elastic` default), AUD-17 (mesh TLS, `:?` secret guard), AUD-18 (secrets off argv; erasure audit fails closed).
2. **Supply chain batch:** AUD-38 to AUD-43 (hash-locked deps, digest-pinned images, pinned CI tools with checksums, workflow `permissions:`, Trivy HIGH + Elastic images, Dependabot config, required lint checks, CODEOWNERS coverage).
3. **Refactors:** AUD-19, AUD-20 (split `agent.py`, keep re-exports; shared `lib/soc_hmac.py` and `lib/soc_http.py`), AUD-33 (pooled session + async work queue), AUD-36 (ES-backed nonce store, removes the 1-worker pin).
4. **Correctness polish:** AUD-16 (LLM boundary), AUD-24 to AUD-26, AUD-31, AUD-34, AUD-35, AUD-37.
5. **Docs and style:** AUD-22, AUD-23, AUD-30 (mypy ratchet), AUD-32 (hermetic SLO tests); move review history out of comments into `findings/`.

### Automated guardrails — where to add analysis tooling in CI/CD

| Stage | Tool (already present → add) | What it enforces | Findings it would have caught |
|---|---|---|---|
| **Pre-commit (local)** | ruff, shellcheck → add `pre-commit` with ruff `S` (bandit) rules, `gitleaks protect`, `hadolint` | Shell-injection-prone patterns (`S602/S604`), secrets, Dockerfile pinning | AUD-38, AUD-13 (Dockerfile), parts of AUD-01 |
| **PR — SAST** | CodeQL (python, default) → **`security-extended` + `actions` language**; **Semgrep** with a custom rule: "value from `ipaddress.ip_address()` input interpolated into an f-string passed to `conn.run`/`subprocess`" | Taint flows to command sinks; workflow injection | AUD-01, AUD-40 |
| **PR — SCA / supply chain** | pip-audit → **GitHub Advanced Security dependency review action** (block on new HIGH), **Dependabot** (`pip`, `docker`, `github-actions`), `pip install --require-hashes`; optional **Snyk** for container base-image remediation advice | Vulnerable/drifting deps; unpinned digests | AUD-28, AUD-38, AUD-41 |
| **PR — IaC / config** | Trivy config (`scripts/setup`) → **Trivy config on `.`**, **Checkov** for compose + GitHub Actions, **zizmor** for workflow hardening, **actionlint** | `permissions:`, `persist-credentials`, missing `cap_drop`, privileged mounts | AUD-13, AUD-40, AUD-42 |
| **PR — quality gate** | pytest-cov 70% (reporting only) → **SonarQube/SonarCloud quality gate** (or `diff-cover`) on *new code*: coverage ≥ 85%, no new Critical/Blocker issues, duplication < 3%, cognitive complexity per function ≤ 25 | God functions, duplication, untested new code | AUD-19, AUD-20, AUD-29 |
| **PR — type safety** | mypy lenient → mypy `check_untyped_defs` ratchet (fail if error count rises) | Untyped bodies | AUD-23, AUD-30 |
| **PR — policy tests (repo-specific)** | `tests/pipeline/*` → add: (a) ES role JSON may not grant `manage`/`delete*` on `soc-audit-*`/`logstash-*`; (b) every unit that copies the CA calls `verify_ca_fingerprint.sh`; (c) CI installs from `requirements.txt` (no hand pins); (d) every `tests/**/test_*.py` is reached by some workflow | Least privilege, CA pinning, test drift | AUD-03, AUD-05, AUD-12, AUD-27, AUD-28 |
| **Build** | Trivy image (CRITICAL) → Trivy `HIGH,CRITICAL` incl. Elastic images; **SBOM** (`syft`) attached to each image; **cosign** signing | Image vulns; provenance (SR-4) | AUD-41 |
| **Post-deploy (local `live-fire`, non-required)** | Live-fire Sigma → add ES `_has_privileges` assertions and an "unauthenticated `:5514` / forged-dataset event must not trigger `/alert`" check | Live RBAC and trust-boundary regressions | AUD-02, AUD-05 |
| **Continuous** | GitHub secret scanning + push protection; Dependabot alerts; CodeQL weekly schedule (present) | Drift between PRs | — |

Branch protection must list each new gate as a required check (update `setup_branch_protection.sh` `REQUIRED_CHECKS`; repo-admin action, local session).

---

## Appendix A — Controls done well (keep these)

- **HMAC everywhere it applies:** constant-time compare, ±300 s timestamp window, nonce recorded only after a valid signature, domain separation of request vs response (`agent.py:270-366`, `app.py:285-338`). Startup refuses reused secrets across channels (`agent.py:180-236`).
- **At-most-once approval:** ES `op_type=create` claim with `if_seq_no` re-win, three-state outcome (success / confirmed-fail / unknown) that never releases a claim on an unknown result (`checkpoints.py:198-257`, `agent.py:1508-1650`).
- **Fail-closed exclusion list** with CIDR support on both services (`agent.py:817-879`, `dispatcher.py:67-122`); `NFT_BLOCKLIST_SET` validated as an identifier at import (`dispatcher.py:158-162`); strict SSH host-key checking by default (`dispatcher.py:40-58`).
- **The LLM never decides an action**; hosted egress off by default; notifications mask IOCs incl. IPv6 /64.
- **Tenant id validated** at Logstash (`logstash.conf:69-74`) and both services, same grammar everywhere.
- **TLS verification never disabled** in Python code; mTLS required on Beats; ES/agent/broker bound to 127.0.0.1.
- **Non-root containers**, single-worker pin documented with its reason; systemd timers heavily sandboxed with CA fingerprint pinning on SLO/health lanes.
- **CI:** every action pinned by full SHA; no `pull_request_target`, `continue-on-error` or `|| true`; gitleaks over full history; time-boxed Trivy exception with justification; detection-as-code gates with fixture/playbook/coverage coupling.

## Appendix B — Next step under the brief's follow-up protocol

The brief's follow-up asks for one Critical item at a time, on its own `remediation/issue-<n>-nist` branch, with a diff shown and owner approval **before** any file is modified. The recommended first item is **C1 (AUD-01)**: smallest change, highest severity, fully testable in a cloud session, and every valid unscoped IP keeps byte-identical behaviour.
