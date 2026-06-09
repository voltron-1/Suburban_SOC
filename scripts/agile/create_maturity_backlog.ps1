# Creates the SOC maturity roadmap backlog: 4 milestones (Phases 0-3),
# 23 [User Story] issues (one per workstream), and places them on the
# project board with Status/Priority/Size set.
#
# Source of truth for the work: docs/SOC-maturity-roadmap.md
# Idempotent: skips milestones/issues whose titles already exist.

$Repo          = 'sterlinggarnett/Suburban_SOC'
$Owner         = 'sterlinggarnett'
$ProjectNumber = 4
$ProjectId     = 'PVT_kwHOD4fhTM4BU152'
$StatusField   = 'PVTSSF_lAHOD4fhTM4BU152zhFKt6M'
$PriorityField = 'PVTSSF_lAHOD4fhTM4BU152zhFK43A'
$SizeField     = 'PVTSSF_lAHOD4fhTM4BU152zhFK43k'

$St = @{ Backlog='f75ad846'; Ready='e18bf179'; InProgress='47fc9ee4'; InReview='aba860b9'; Done='98236657' }
$Pr = @{ P0='79628723'; P1='0a877460'; P2='da944a9c' }
$Sz = @{ XS='911790be'; S='b277fb01'; M='86db8eb3'; L='853c8207'; XL='2d0801e2' }

function New-Body($story, [string[]]$tasks, $accept, $files) {
    $t = ($tasks | ForEach-Object { "- [ ] $_" }) -join "`n"
    return @"
$story

### Tasks
$t

**Acceptance:** $accept

**Files:** $files

_Ref: ``docs/SOC-maturity-roadmap.md``_
"@
}

# --- 1. Milestones -----------------------------------------------------------
$milestones = @(
    @{ key='P0'; title='Milestone 7: Platform Security & Multi-Tenancy Foundation';
       desc='Phase 0 ship-blockers: authenticate/encrypt the stack, secure the response webhook, multi-tenant isolation, secrets, retention. No customer deploy before this closes.' }
    @{ key='P1'; title='Milestone 8: Detection Plane - NIST CSF Coverage & ATT&CK Depth';
       desc='Phase 1: detection-as-code, live threat intel, confirmed data sources, published ATT&CK coverage matrix, SOAR-trigger fix.' }
    @{ key='P2'; title='Milestone 9: Operational Maturity (SOC-CMM Level 3)';
       desc='Phase 2: detection CI/CD, threat hunting, case tracking, self-measuring metrics/SLOs, HA + restore-tested backups.' }
    @{ key='P3'; title='Milestone 10: SOC 2 Type II Technical Control Readiness';
       desc='Phase 3: encryption, RBAC, tamper-evident audit trail, privacy/data-deletion, change mgmt, vuln scanning, continuous control monitoring.' }
)

$existingMs = gh api "repos/$Repo/milestones?state=all&per_page=100" | ConvertFrom-Json
$msTitle = @{}
foreach ($m in $milestones) {
    $hit = $existingMs | Where-Object { $_.title -eq $m.title }
    if ($hit) {
        Write-Host "Milestone exists: $($m.title)"
    } else {
        gh api "repos/$Repo/milestones" -f title="$($m.title)" -f description="$($m.desc)" | Out-Null
        Write-Host "Created milestone: $($m.title)"
    }
    $msTitle[$m.key] = $m.title
}

# --- 2. Issue definitions ----------------------------------------------------
$issues = @(
    # ---------- Phase 0 (M7, P0) ----------
    @{ title='[User Story] WS0.6 Consolidate the duplicate Logstash config'; ms='P0'; pri='P0'; size='S'; status='InProgress';
       body=(New-Body 'As a SOC engineer, I want a single source of truth for the Logstash pipeline so that security fixes cannot land in one copy and silently drift from the other.' `
        @('Pick canonical path and remove the duplicate copy step in deploy_dashboards.sh',
          'Bind the canonical file directly in docker-compose.yml (symlink or volume)',
          'Verify `docker compose config` resolves to the single file') `
        'One logstash.conf; no sync step; compose resolves to it.' `
        'configs/logstash.conf, scripts/setup/configs/logstash/logstash.conf, scripts/setup/docker-compose.yml, scripts/setup/deploy_dashboards.sh') }

    @{ title='[User Story] WS0.1 Authenticate & encrypt the Elastic stack'; ms='P0'; pri='P0'; size='M'; status='Ready';
       body=(New-Body 'As a SOC operator, I want the Elastic stack authenticated and TLS-encrypted so that the monitoring platform itself is not an open data store.' `
        @('Enable xpack.security + TLS (transport+HTTP) in docker-compose.yml',
          'Put Kibana behind login with a service account',
          'Logstash + Filebeat ship via scoped API keys, not the elastic superuser',
          'Parameterize the ES output credentials in logstash.conf') `
        'Anonymous curl to ES:9200 returns 401; Kibana requires login; Logstash uses an API key.' `
        'scripts/setup/docker-compose.yml, configs/logstash.conf, configs/network/filebeat.yml, configs/endpoint/*.yml') }

    @{ title='[User Story] WS0.2 Authenticate & harden the response webhook'; ms='P0'; pri='P0'; size='M'; status='Ready';
       body=(New-Body 'As a SOC operator, I want the /alert webhook authenticated and input-validated so that no one who reaches port 5000 can quarantine arbitrary devices.' `
        @('Require HMAC-signed requests on /alert (mirror the hive-mind-broker pattern)',
          'Regex-validate MAC and IP before any subprocess call',
          'Reject unsigned/invalid requests with 401/400 and never invoke isolate.sh',
          'Add defensive input validation at isolate.sh entry too',
          'Add a unit test asserting forged POST does not trigger isolation') `
        'Unsigned POST -> 401 and no isolate.sh call; malformed MAC/IP -> 400.' `
        'scripts/setup/ai_agent/agent_app.py, scripts/setup/isolate.sh') }

    @{ title='[User Story] WS0.4 Secrets management'; ms='P0'; pri='P0'; size='S'; status='Backlog';
       body=(New-Body 'As a SOC engineer, I want all secrets out of the repo so that router/LLM/ES credentials are never committed.' `
        @('Move inventory.yaml creds to env/secret store; commit inventory.example.yaml only',
          'Remove default secrets from agent_app.py (LLM key, ntfy topic)',
          'Wire secrets via env_file/Docker secrets in docker-compose.yml',
          'Add gitleaks/trufflehog secret scanning to CI') `
        'gitleaks detect is clean; no functional default secret in code.' `
        'scripts/hive-mind-broker/inventory.yaml, scripts/setup/ai_agent/agent_app.py, scripts/setup/docker-compose.yml') }

    @{ title='[User Story] WS0.3 Multi-tenancy foundation'; ms='P0'; pri='P0'; size='L'; status='Backlog';
       body=(New-Body 'As a SOC operator serving many homes, I want every event, dashboard, alert and response scoped to a tenant so that one customer can never see or affect another.' `
        @('Stamp tenant.id at the edge (per-tenant Filebeat fields or pipeline) + guard in logstash.conf',
          'Route to per-tenant data streams/indices instead of one logstash-security-*',
          'Kibana Spaces per tenant + ES roles (optionally document-level security)',
          'Tenant-scope isolate.sh / broker router resolution (never broadcast across tenants)',
          'Per-tenant ntfy topic / Discord webhook (remove hardcoded values)') `
        'Tenant-A role returns zero tenant-B docs; a quarantine for A touches only A''s router.' `
        'configs/logstash.conf, configs/network/filebeat.yml, configs/endpoint/*.yml, scripts/setup/ai_agent/agent_app.py, scripts/setup/isolate.sh, scripts/hive-mind-broker/, configs/server/*.ndjson') }

    @{ title='[User Story] WS0.5 Data lifecycle & retention'; ms='P0'; pri='P0'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want a defined retention/ILM policy so that storage is bounded and the evidence window is explicit.' `
        @('Convert indices to data streams',
          'Define ILM hot/warm/delete with a documented retention window',
          'Snapshot before delete',
          'Install policies via deploy script') `
        'ILM policy attached; rollover observed; retention documented and enforced.' `
        'configs/elasticsearch/ilm/*.json, configs/logstash.conf, scripts/setup/deploy_dashboards.sh') }

    # ---------- Phase 1 (M8) ----------
    @{ title='[User Story] WS1.1 Fix the dead SOAR trigger & remove hardcoded detection'; ms='P1'; pri='P1'; size='S'; status='Backlog';
       body=(New-Body 'As a SOC engineer, I want the SOAR trigger to fire on a real intel match so that automated response actually happens, and no detection logic is hardcoded.' `
        @('Drive SOAR off the intel-match pipeline (Zeek Intel::Notice -> ECS threat.indicator.*)',
          'Remove hardcoded IOC 185.150.115.115 from logstash.conf',
          'Source the ntfy topic from tenant config',
          'Add a simulation asserting an intel hit triggers /alert') `
        'A test IOC in the feed triggers /alert end-to-end.' `
        'configs/logstash.conf, configs/intel/, tests/anomaly_simulation/') }

    @{ title='[User Story] WS1.2 Detection-as-code: real Sigma pipeline'; ms='P1'; pri='P1'; size='L'; status='Backlog';
       body=(New-Body 'As a detection engineer, I want Sigma rules converted to Elastic detection rules by a real backend so that detection logic lives in version-controlled rules, not inline pipeline regex.' `
        @('Add sigma CLI + pySigma-backend-elasticsearch conversion at deploy',
          'Promote rules past experimental only after passing tests',
          'Thin logstash.conf to enrichment/normalization (remove inline regex detections)',
          'Add scripts/setup/deploy_detections.sh + CI job') `
        'deploy_detections.sh loads rules into Elastic; inline regex detections removed.' `
        'rules/sigma/, scripts/setup/deploy_detections.sh, configs/logstash.conf') }

    @{ title='[User Story] WS1.3 Live threat intelligence'; ms='P1'; pri='P1'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC analyst, I want an auto-refreshing threat-intel feed so that detections reflect current indicators instead of two static entries.' `
        @('Automate feed refresh (MISP / abuse.ch / OTX) into Zeek Intel framework + an ES intel index',
          'Emit ECS threat.indicator.* on matches',
          'Add a feed-freshness panel and stale-feed alert') `
        'Feed auto-updates on schedule; a known-bad test indicator matches; stale feed alerts.' `
        'configs/intel/, configs/zeek/local.zeek, configs/server/*.ndjson') }

    @{ title='[User Story] WS1.4 Confirm & expand data sources'; ms='P1'; pri='P1'; size='M'; status='Backlog';
       body=(New-Body 'As a detection engineer, I want endpoint telemetry proven to flow and a passive asset inventory so that endpoint detections actually fire and NIST Identify is covered.' `
        @('Prove Sysmon/Winlogbeat + Linux auth telemetry flows per tenant',
          'Build passive asset inventory from Zeek conn/known_hosts/known_services',
          'Evaluate Suricata for signature coverage alongside Zeek') `
        'Data Quality dashboard shows a live heartbeat per source per tenant; asset list populated.' `
        'configs/endpoint/*, configs/zeek/local.zeek') }

    @{ title='[User Story] WS1.5 Publish the ATT&CK coverage matrix'; ms='P1'; pri='P1'; size='S'; status='Backlog';
       body=(New-Body 'As a SOC lead, I want a published ATT&CK coverage matrix so that detection breadth/depth and gaps are explicit and prioritized.' `
        @('Build a machine-readable matrix: data source -> technique -> rule -> test',
          'Render an ATT&CK Navigator layer',
          'Annotate gaps and create a backlog for next tactics (Collection, Exfil, C2, Lateral Movement)') `
        'Navigator layer renders; every deployed rule appears; gaps annotated.' `
        'docs/detections/attack-coverage.json') }

    # ---------- Phase 2 (M9) ----------
    @{ title='[User Story] WS2.1 Detection-engineering CI/CD'; ms='P2'; pri='P1'; size='L'; status='Backlog';
       body=(New-Body 'As a detection engineer, I want every detection covered by a test that runs in CI so that a change which breaks a rule is caught before merge.' `
        @('Add a test per detection (logic + replayable PCAP/log fixture) asserting it fires with correct ATT&CK/NIST tags',
          'Run detection tests in CI on every PR',
          'Gate promotion experimental -> test -> stable on green',
          'Add a false-positive regression suite') `
        'A PR that breaks a rule fails CI; coverage report lists rule->test.' `
        'tests/, .github/workflows/detections.yml, rules/sigma/') }

    @{ title='[User Story] WS2.2 Threat-hunting capability'; ms='P2'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC analyst, I want a versioned, scheduled hunt library so that proactive hunting is repeatable and feeds new detections.' `
        @('Create hunts/ with hypothesis-driven queries (query + hypothesis + expected data source)',
          'Schedule hunts and align the backlog to ATT&CK',
          'Promote at least one hunt finding into a detection') `
        '>=5 hunts versioned and scheduled; one finding promoted to a detection.' `
        'hunts/, scripts/setup/deploy_dashboards.sh') }

    @{ title='[User Story] WS2.3 Alert triage & case tracking'; ms='P2'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC analyst, I want each alert to have case state/owner/timeline so that triage is tracked rather than fire-and-forget notifications.' `
        @('Use Kibana Cases (or TheHive) for alert state, owner, timeline (tenant-scoped)',
          'Attach AI triage summary + SOAR action to the case from agent_app.py',
          'Support disposition/close-out') `
        'An /alert produces a case with AI summary + action recorded, closeable with disposition.' `
        'configs/server/, scripts/setup/ai_agent/agent_app.py') }

    @{ title='[User Story] WS2.4 Self-measuring metrics & SLOs'; ms='P2'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC lead, I want MTTD/MTTR, coverage and pipeline-health measured against targets so that the SOC quantifies its own performance.' `
        @('Automate MTTD/MTTR vs defined targets',
          'Track detection-coverage % and false-positive rate',
          'Add pipeline SLOs (ingest lag, drop rate) with breach alerting') `
        'Dashboard shows each metric vs target; SLO breach raises an alert.' `
        'configs/server/executive_dashboard.ndjson, scripts/setup/ai_agent/weekly_ciso_report.py') }

    @{ title='[User Story] WS2.5 Reliability of the SOC stack'; ms='P2'; pri='P1'; size='L'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want the stack to be highly available with restore-tested backups and self-monitoring so that a paying customer gets uptime and recoverable evidence.' `
        @('Move to multi-node ES (or managed) for HA',
          'Automate snapshots to object storage with periodic restore tests',
          'Enable Stack Monitoring on the SOC''s own components with alerting') `
        'Killing a node keeps the cluster serving; a snapshot restores; component-down alerts.' `
        'scripts/setup/docker-compose.yml, configs/elasticsearch/snapshot/*') }

    # ---------- Phase 3 (M10, P2) ----------
    @{ title='[User Story] WS3.1 Encryption in transit & at rest'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want encryption everywhere so that customer telemetry is protected on the wire and on disk (SOC 2 Security/Confidentiality).' `
        @('TLS on every hop (Filebeat->Logstash->ES, agent, broker) - builds on WS0.1',
          'Encryption at rest for the ES data volume and snapshots') `
        'A transit capture shows no plaintext telemetry; at-rest encryption confirmed.' `
        'scripts/setup/docker-compose.yml, configs/') }

    @{ title='[User Story] WS3.2 RBAC & least privilege'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want least-privilege roles so that no human or service uses a shared superuser in normal operation (SOC 2 Security).' `
        @('Define roles: tenant-viewer, analyst, detection-engineer, admin, service accounts',
          'Scope Logstash/Filebeat/agent to API keys, not the elastic superuser',
          'Add negative tests proving each account can only do its job') `
        'Each service account can do only its job; no routine superuser use.' `
        'configs/elasticsearch/roles/*') }

    @{ title='[User Story] WS3.3 Tamper-evident audit trail'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want a tamper-evident audit trail of all admin and response actions so that every privileged action is accountable (SOC 2 Security).' `
        @('Enable ES/Kibana audit logging',
          'Capture every quarantine/config/rule change with actor + tenant',
          'Ship audit logs to an append-only/immutable store with retention') `
        'Every privileged action is queryable with who/what/when/tenant; audit store is write-once.' `
        'scripts/setup/docker-compose.yml, scripts/setup/ai_agent/agent_app.py, scripts/setup/isolate.sh') }

    @{ title='[User Story] WS3.4 Privacy & data-handling controls'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator capturing residents'' traffic, I want privacy controls so that capture scope, PII minimization, retention and right-to-erasure are enforced (SOC 2 Confidentiality/Privacy).' `
        @('Enforce documented capture scope in Zeek config',
          'Minimize PII where feasible; enforce retention limits (ties to WS0.5)',
          'Implement per-tenant data deletion (right-to-erasure) with a runbook+script') `
        'A tenant-deletion request provably removes that tenant''s data within the SLA window.' `
        'configs/zeek/local.zeek, configs/elasticsearch/ilm/') }

    @{ title='[User Story] WS3.5 Change management on detections & config'; ms='P3'; pri='P2'; size='S'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want enforced review + CI gates on detection/config/response changes so that nothing reaches prod unreviewed (SOC 2 Security).' `
        @('Enforce PR review + branch protection on rules/, configs/, response code',
          'Require CI gates (WS2.1) to pass',
          'Emit a deployment changelog from deploy scripts') `
        'No detection/config reaches prod without a reviewed, CI-passed, recorded change.' `
        '.github/, scripts/setup/deploy_*.sh') }

    @{ title='[User Story] WS3.6 Vulnerability management of the SOC stack'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC operator, I want the SOC''s own images and dependencies scanned and patched so that the platform is not the weak link (SOC 2 Security).' `
        @('Pin + scan container images (Trivy/Grype)',
          'Scan Python deps (ai_agent, hive-mind-broker requirements.txt)',
          'Define a patch cadence; fail CI on critical CVEs') `
        'CI blocks a known-critical CVE; patch cadence documented and met.' `
        '.github/workflows/, scripts/setup/ai_agent/Dockerfile, requirements.txt') }

    @{ title='[User Story] WS3.7 Continuous control monitoring'; ms='P3'; pri='P2'; size='M'; status='Backlog';
       body=(New-Body 'As a SOC lead, I want technical-control status auto-collected so that a regression (e.g. auth disabled) is detected continuously rather than at audit time.' `
        @('Auto-collect control evidence: auth on, TLS on, ILM attached, snapshots succeeding, audit logging on, scans passing',
          'Surface a control-status dashboard / periodic report',
          'Alert when a control regresses') `
        'A single view shows each control''s live status; a regressing control alerts.' `
        'configs/server/, scripts/setup/ai_agent/') }
)

# --- 3. Create issues + place on board --------------------------------------
$existingIssues = gh issue list --repo $Repo --state all --limit 300 --json title --jq '.[].title'
$created = 0
foreach ($i in $issues) {
    if ($existingIssues -contains $i.title) { Write-Host "Issue exists, skipping: $($i.title)"; continue }

    $url = gh issue create --repo $Repo --title $i.title --body $i.body `
                           --label 'user-story' --assignee '@me' --milestone $msTitle[$i.ms]
    $url = ($url | Select-Object -Last 1).Trim()
    Write-Host "Created: $($i.title) -> $url"

    $item = gh project item-add $ProjectNumber --owner $Owner --url $url --format json | ConvertFrom-Json
    $itemId = $item.id

    gh project item-edit --id $itemId --project-id $ProjectId --field-id $StatusField   --single-select-option-id $St[$i.status] | Out-Null
    gh project item-edit --id $itemId --project-id $ProjectId --field-id $PriorityField --single-select-option-id $Pr[$i.pri]    | Out-Null
    gh project item-edit --id $itemId --project-id $ProjectId --field-id $SizeField     --single-select-option-id $Sz[$i.size]   | Out-Null
    $created++
}

Write-Host ""
Write-Host "Done. Created $created new issue(s) across milestones M7-M10 and placed them on the board."
