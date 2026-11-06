# Claims-to-evidence remediation plan (FOB / funding-briefing readiness)

Status: **DRAFT FOR OWNER REVIEW. Nothing here is started.** Written 2026-11-04.
Sources: README.md (Architecture, Status, Known Issues), `plans/20261023-production-readiness-plan.md`, `plans/20261024-session-handoff.md`,
`scripts/setup/.env.example` (L128-141), `scripts/setup/docker-compose.ha.yml`. Anything not read is marked **UNVERIFIED**.

## 0. Goal and rule

Goal: every claim we want to make to a funding audience is backed by an artifact a skeptic can inspect.
Rule: **a claim is "proven" only when its exit gate below is met and the evidence file is committed.** Until then the
claim stays in the "do not say" column of the register (section 2). Where a claim cannot be proven in this repo
(third-party certification), we reword it to what we can prove instead of chasing it.

This plan extends, and does not replace, `plans/20261023-production-readiness-plan.md` (items 1-8). Overlaps are
cross-referenced; this plan adds the claim-by-claim proof criteria and the gaps that plan does not cover.

## 1. What the repo already gives us (verified this session)

- Hosted-LLM egress is **off by default**: `LLM_ALLOW_HOSTED=false`; the agent degrades gracefully and a local Ollama URL is supported
  (`.env.example` L135-141; `agent.py` L903-914, L985). The air-gap story is therefore a *test-and-document* job, not a rewrite.
- Multi-node ES exists as `scripts/setup/docker-compose.ha.yml` (ES_JAVA_OPTS 1g per node). Whether it is exercised by CI or ever
  failed over: **UNVERIFIED**.
- External egress paths that exist today: `ntfy.sh` (`agent.py` L1061), Discord webhook (L1076), public threat-intel feeds
  (Feodo, Emerging Threats), hosted LLM if enabled. These must each be gated or have an offline alternative.

## 2. Claims register (the spine of this plan)

| # | Claim we want | Today's evidence | Gap | Phase |
|---|---|---|---|---|
| C1 | Sensor sees the network, not one host | Only this PC's traffic (78/109 conn records from one IP); no host DNS (#593, #592) | Placement + DNS capture | P0 |
| C2 | An attack produces an alert a human receives | Delivery to owner's phone verified live (#567 closed, `NTFY_TOPIC` set, per handoff); **attack-triggered end-to-end run never done** (needs a second LAN host); standing 15-min SLO push noise | e2e run, noise fix | P0 |
| C3 | Features shipped are live-validated | #265 done for Linux/Filebeat only; PR #564 mostly deployed; #443/#444, #585 tooling and Windows endpoints still unproven live | Remaining live runs | P0 |
| C4 | Detections fire on live data | Live-fire covers 1 rule per category; rest logic-only (README L492) | Per-rule live proof or honest coverage table | P1 |
| C5 | Coverage claims map to ATT&CK honestly | Corpus 108 rules; no rule-to-technique truth table | Coverage truth table, generated | P1 |
| C6 | Human-gated response works and is fast | Approval gate hardened (M12/M14); MTTD/MTTR never recorded (#147) | Measured MTTD/MTTR from real runs | P1 |
| C7 | Encrypted-traffic visibility (metadata) | HTTPS payload blind (README L489); TLS/SNI fields mapped | Prove what TLS metadata detects; scope claim to metadata | P1 |
| C8 | Holds up under load | "Performance under extreme load is unknown" | Benchmark with published numbers | P2 |
| C9 | Survives node loss | Single-node ES, no replicas (README L488) | HA bring-up + kill-a-node test | P2 |
| C10 | Operates disconnected from the internet | Defaults favor it; never tested | Zero-egress test, local LLM, offline intel | P3 |
| C11 | Runs on defined deployable hardware | Runs on a WSL2 host | Reference hardware profile + measured footprint | P3 |
| C12 | Supply chain is controlled | zeek image CVE exception expires 2026-11-25 (#577) | SBOM, pinned digests, exception closed | P4 |
| C13 | Control maturity is evidenced | SOC 2 / SOC-CMM are design/self-assessed (README L93-103) | Populate evidence ledger; **reword**, do not chase certification | P4 |

Claims we will **not** upgrade by work in this repo (reword only): "SOC 2 Type II certified", "SOC-CMM L3 rated" (need an
external auditor/assessor), "decrypts HTTPS" (out of scope per README L361-363 unless the owner re-scopes), "combat/contested-ready".

## 3. Owner decisions needed before Phase 0 starts

1. **Sensor placement (#593):** router mirror/capture path, a mirror port, or stay single-host and reword. Recommended: router capture
   path, because the architecture table already assumes the OpenWrt boundary. Needs the router's real capabilities (**UNVERIFIED**).
2. **Notification channel for the briefing environment:** ntfy.sh and Discord are public third-party services. Recommended: keep them as
   optional, add a self-hostable channel (self-hosted ntfy or local webhook) for the disconnected profile.
3. **Target reference hardware** (C11): which box do we claim to run on? Any answer is fine; it must be a real, measured one.
4. **Local LLM model/size** for C10: needs a hardware answer from decision 3.
5. **Load target** (C8): expected peak events/sec and bytes/sec for the intended site. Unknown today; the readiness plan item 4 also blocks on it.
6. **Evidence handling:** confirm nothing from `evidence/` or live captures with real IPs/MACs goes into a briefing without scrubbing.

## 4. Phases

Execution rules (from CLAUDE.md): one phase at a time; after each phase I surface changes, source agents, and verified exit-gate
criteria, then **wait for your explicit go-ahead**. Each phase lands as small PRs; no closing keywords in PR text (leave issues open
and close manually after merge). Work needing Docker/ES/the capture host runs from a local session, with Docker Desktop started.

### Phase 0 - Make the base real (C1, C2, C3)
> **CORRECTION 2026-11-04 (after verification, see `findings/20261104-plan-claim-verification.md`).** The table below is the handoff's statuses as of 2026-10-24.
> Checked on this host today they do **not** hold: `zeek-host-capture.service` is `failed` (exit 78, since 2026-11-03 10:34 CST), `conn.log` is ~4.7 days stale, only `eth0`
> (`172.21.123.120/20`, WSL NAT) exists with no `192.168.1.x` or `eth1`, `NTFY_TOPIC` is empty in `scripts/setup/.env`, and no Docker project from this repo is running.
> Treat every "DONE" below as **UNVERIFIED / possibly regressed** until re-proven. New **P0.0 (first): restore the baseline.** Root causes found (findings file, section C):
> (1) `/etc/default/zeek-host-capture` pins `CAPTURE_IFACE=eth1`, which does not exist after the WSL restart, so the preflight exits 78 (`FATAL: capture interface "eth1" is not up`);
> 14 WSL boots occurred 2026-10-26..11-03, so this will recur; (2) `NTFY_TOPIC is unset` (684 log lines), so the failure alert fires but delivers nothing; (3) the SOC compose
> stack does not come back after a WSL restart. A durable fix (stable interface selection or autostart plus a topic that survives restarts) is part of P0.0, not just a one-off edit. This also means claim C2 ("alerts reach a human") is
> currently unproven, and the M26 failure class (a silent capture outage) has recurred.

**Settled 2026-11-04 against `plans/20261024-session-handoff.md` as refreshed by #597.** Statuses below are the handoff's own, not re-verified by me on the host.

| Task | Status | Basis |
|---|---|---|
| P0.2 #567 rate limit + `NTFY_TOPIC` | **DONE** | Handoff 3.2: #567 closed after a live check, topic set, PR #595 throttle verified live |
| P0.4a #265 endpoint client certs | **DONE (Linux/Filebeat only)** | Handoff 3.4: event shipped over mTLS and found, #265 closed. Winlogbeat/Windows not exercised. **Open gap: Logstash trusts the shipper's own `[tenant][id]`** (a multi-tenant integrity issue, now P0.6) |
| P0.4b PR #564 live deploy | **PARTLY DONE** | Units redeployed, 40-rule import and both syslog rules enabled in Kibana (43 total). `zeek-capture-liveness` timer scheduled. Failure-injection of the alert dispatcher not recorded |
| P0.3 end-to-end attack test (runbook Part 6) | **OPEN** | Blocked on a second LAN machine. Runbook done-when is only "`verify_detections.py` finds `Scan::Port_Scan`"; this plan's gate (below) is stricter and still applies |
| P0.1 placement #593 / DNS #592 | **OPEN, owner decision** | Sensor sees only this host (78/109 conn records from one IPv4); WSL2 resolver traffic stays on `lo` |
| P0.4c #443/#444 Suricata live | **OPEN** | #587: distro `suricata.service` enabled, repo unit disabled; Filebeat reads `/storage/PCAP/suricata/eve.json`, distro default path unverified; SLO shows `suricata_ingest_lag_seconds` breach |
| P0.5 Filebeat fingerprint skip #591 | **OPEN** | Needs a design choice |

Remaining tasks
- P0.1 Implement sensor placement per decision 1; fix host DNS visibility (#592) or document the exact blind spot. *code-reviewer, security-auditor.*
- P0.3 Run runbook Part 6 end to end from a second LAN host: scan -> Zeek -> ES -> alert -> ntfy/Discord -> `/approve`. Record timestamps at each hop. *tester-debugger.*
- P0.4c Make Suricata data reach ES (resolve the eve.json path, one unit as the owner), then close #443/#444 by hand only on their own done-when. *tester-debugger.*
- P0.5 Fix Filebeat fingerprint skip (#591).
- P0.6 **(new)** Close the tenant-trust gap: Logstash must derive `[tenant][id]` from the authenticated client certificate, not accept the shipper's value. This is the claim-C13/multi-tenant integrity hole left by #265. *security-auditor.*
- P0.7 **(new)** Stop the standing alert noise: `slo_metrics.py` pushes to the owner's phone every 15 minutes while the Suricata breach stands (handoff 3a). A permanent breach trains the operator to ignore pushes, which undermines claim C2. Either fix P0.4c or mute that one metric with a recorded reason. *code-reviewer.*
Exit gate (all must hold)
- A scan from a *different* host appears in `logstash-security-*` with that host's source IP (query output saved).
- A push notification is received on a device; screenshot with timestamp; journal lines for each hop.
- Induced capture-unit failure produces exactly one alert within the rate-limit window, not one per restart.
- #265, #443, #444 each closed by hand only after their own "done when" is shown in the findings file.
Evidence: `findings/YYYYMMDD-p0-live-validation.md` (commands + verbatim output, no secrets).

### Phase 1 - Prove detection (C4, C5, C6, C7)
Tasks
- P1.1 Extend live-fire from 3 representative rules to **every enabled rule**: fixture -> real ES -> expected hit. Where a rule cannot be live-fired
  (needs Windows telemetry, #326), mark it `logic-only` in the coverage table instead of claiming it. Use the `sigma-validate` skill for the audit. *tester-debugger, purple-team.*
- P1.2 **Extend the existing generator, do not build a new table** (settled 2026-11-04). `scripts/setup/build_attack_coverage.py` already emits
  `docs/detections/attack-coverage.{json,md}` and CI runs `--check` for drift. Verified gaps in it:
  - Every Sigma row's Test column is the same constant, "Detections CI: sigma->Lucene conversion + fixture replay" (L371), i.e. logic-only. It never says which rules are live-fired.
  - The headline "86 techniques across 12 tactics" counts the whole corpus. The corpus is 122 Sigma rules: **94 `experimental`, 26 `stable`, 2 `test`**, and
    `deploy_detections.sh` imports only `test|stable` (28 rules, matching the "28 Sigma-derived + 12 threshold" deploy rows). So most of the
    claimed techniques are not deployed. The generator already captures `status` per row (L325, L364) but the rendered matrix has no status column and the headline ignores it.
  - Live-fire proof exists for **8 of 122** rules (`test_live_fire.py`: powershell_encoded, zeek_executable_download, dns_dga_burst, dns_doh_non_standard,
    dns_txt_answer_abuse, dns_crypto_mining_pool, linux_su_session_opened, win_pass_the_hash_logon). Suricata is deliberately not harvested (scoped out of #445).
  Change: add `Deployed` (status in test|stable, plus threshold rules) and `Proof` (`live-fired` from a list derived from `test_live_fire.py`, else `logic-only`) columns;
  split the headline into "techniques with a deployed rule" and "techniques live-fired"; keep the existing `--check` gate. Claim language in the briefing quotes the
  deployed and live-fired counts, never the corpus count. *purple-team, code-reviewer.*
- P1.3 Run the anomaly-simulation suite (T1046, T1110, EICAR, intel match) repeatedly; compute MTTD and MTTR from timestamps per #147. Report medians and worst case,
  with n. *tester-debugger.*
- P1.4 TLS-metadata detections: enumerate what the existing SNI/cert/TLS fields detect and fire one case live. Rewrite the claim as "metadata analysis of encrypted traffic". *purple-team.*
- P1.5 Tune the 14 threshold Suricata rules against real traffic (#587) or leave them disabled and say so.
Exit gate
- Coverage table shows live-fired count / total; every briefing number comes from it.
- MTTD/MTTR table with n >= 20 runs per scenario (n chosen by me for plausibility; **owner may change**), raw timestamps committed.
Evidence: `findings/YYYYMMDD-p1-detection-proof.md`, `docs/detections/coverage-truth-table.md`.

### Phase 2 - Prove resilience and scale (C8, C9)
Tasks
- P2.1 Load test the OpenWrt -> Zeek -> Filebeat/Logstash -> ES path at 1x, 2x, 5x the decision-5 target; record drop rates, ingest lag (existing SLO metrics),
  CPU/RAM, and the first breaking point. Includes #405 sweep benchmark. *tester-debugger.*
- P2.2 Bring up `docker-compose.ha.yml`; confirm green cluster with replicas; **kill one node under load**; measure time to recover and events lost. *tester-debugger, security-auditor (port exposure).*
- P2.3 Decide replica policy for index templates (currently `number_of_replicas: 0`) for HA profile only.
Exit gate
- Published numbers with test method, hardware, and the failure point. If the system breaks at 1x, that *is* the result; we state it and size the ask accordingly.
- Node-loss test shows no acknowledged-event loss, or the loss is quantified.
Evidence: `findings/YYYYMMDD-p2-load-and-ha.md`.

### Phase 3 - Prove disconnected operation and a deployable profile (C10, C11)
Tasks
- P3.1 Egress inventory test: run the full stack with outbound default-deny except LAN; list every blocked attempt. Anything that fails closed unsafely is a bug. *security-auditor.*
- P3.2 Local-LLM triage: point `LLM_API_URL` at local Ollama (decision 4), run the same alert set, compare triage output and latency to the degraded (no-LLM) path.
  Report that LLM triage is advisory and the response gate is unchanged. *code-reviewer, tester-debugger.*
- P3.3 Offline intel: signed/hashed bundle import path for `intel.dat` (today only network refresh). Preserve the CA-pinning and co-location hardening from M21. *security-auditor.*
- P3.4 Self-hosted notification channel option (decision 2).
- P3.5 Reference deployment profile: one documented, scripted install on the decision-3 hardware, with measured idle/peak footprint and a time-to-deploy measurement
  from bare OS (not WSL2). *code-reviewer.*
Exit gate
- Pcap of a full test run on an isolated segment showing zero packets to non-LAN destinations.
- Alert -> triage -> approval works with Internet unplugged.
Evidence: `findings/YYYYMMDD-p3-disconnected.md`, `docs/reference-deployment.md`.

### Phase 4 - Supply chain and assurance wording (C12, C13)
Tasks
- P4.1 **Settled 2026-11-04: #577 already has a fix in flight, PR #607 (open, not mine).** Branch `fix/issue-577-zeek-9.0.1`, one commit (`0402b52`, 2026-11-03), based on current `main`,
  GitHub reports 19/19 checks SUCCESS, merge state CLEAN, no review recorded. What it does: bumps the zeek pin 9.0.0 -> 9.0.1 (digest-pinned; the 4 capture scripts
  and the unit header carry `zeek/zeek:9.0.1@sha256:524cb0ce...249dd0`), which per the commit message ships the fixed libnode115 and so **retires the CVE-2026-48930 exception**,
  and replaces it with a new time-boxed exception, **expiring 2026-11-30**, for 3 CRITICAL python3-git (GitPython) CVEs that no published image has fixed.
  Verified by me: `git grep` on the branch finds no `zkg`/GitPython use outside comments, which supports the "not reachable as deployed" justification.
  **Verification update (same day, `findings/20261104-plan-claim-verification.md`):** 9.0.1 digest and push date confirmed on Docker Hub; CVE-2026-48930 and
  CVE-2026-111497 confirmed in Debian's tracker with the stated fixed versions; the 3 GitPython CVEs exist and Debian ships `python3-git 3.1.44-1+deb13u1` (so a thin
  pinned layer could remove the finding instead of excepting it, untested). **Live sensor confirmed to be the Docker image** (`host_capture.sh` L74-79), so #607 does
  change it; native `/opt/zeek` is 9.0.1 and not on the live path. **Still unverified:** the Debian page lists nodejs `deb13u3` as vulnerable to CVE-2026-111497 with no
  fix, which conflicts with the commit's "clears" claim; no `dpkg` or local Trivy check of the 9.0.1 image; the **164-pcap golden diff was not run**. Remaining P4.1 work, none done yet:
  (a) owner review and merge of #607 (only the owner merges); (b) run the 164-pcap golden diff from a local session with Docker Desktop up; (c) before 2026-11-30, re-check
  Docker Hub for an image with the python3-git fix and either bump or re-justify, never silently extend; (d) #577 stays open until then, and the briefing may say only
  "scanner-flagged CVEs carry documented, time-boxed non-reachability exceptions", never "zero vulnerabilities".
- P4.2 Pin all images by digest; generate an SBOM per image in CI; Trivy gate stays blocking. *security-auditor.*
- P4.3 Populate `docs/deploy-changelog.md` from real deploys made in P0-P3 (it is the SOC 2 evidence ledger and is empty by README L99-101); the uncommitted
  modification currently in the working tree should be reviewed first.
- P4.4 Rewrite README status language so "Complete" claims match the scope note; remove or qualify any statement the evidence does not support. Reconcile the stale
  README testing section ("will be implemented", L465).
- P4.5 Optional, owner decision: scope an independent assessor for SOC-CMM; SOC 2 needs an auditor and an observation period. Record as cost/schedule in the funding ask, not as a claim.
Exit gate: SBOMs attached to a CI run; zero unexcepted CRITICAL findings; README claims each cite a findings file.

### Phase 5 - Assemble the evidence pack
- P5.1 One claims register, each row `claim -> evidence file -> date -> how to reproduce`. Rows with no evidence stay in "do not say".
- P5.2 Reproducibility check: a person who did not write the code re-runs P0.3 and P1.3 from the docs alone. *Independent agent or second human; I will not self-certify.*
- P5.3 Then, and only then, a briefing outline built from the register.
Exit gate: reviewer reproduces headline numbers within stated variance.

## 5. Sequence and dependencies

P0 -> P1 (needs live pipeline). P2 and P3 can run in parallel after P0 if hardware allows (different test beds). P4.1 is date-driven (2026-11-25 today; 2026-11-30 once #607 merges) and
should be pulled forward now. P5 last. Windows telemetry (#326) is an external blocker for the endpoint half of C4/C5; it does not block the network claims.

## 6. Risks

- Honest results may be unflattering (load ceiling, MTTR). The plan treats a measured limit as a deliverable; it becomes the funding justification.
- Single maintainer: P0-P3 are roughly sequential human-attended live sessions. I have not estimated durations; I would rather size them after Phase 0 gives real data.
- Live phases need Docker Desktop running on the WSL host; if it is stopped, `zeek-host-capture.service` crash-loops silently (project CLAUDE.md).
- Hosted services (ntfy.sh, Discord, public feeds) widen the data-exposure surface; scrub anything from home-network captures before it leaves the host.

## 7. Not in scope

TLS decryption proxy; third-party certification itself; multi-tenant changes; anything that enables `AUTONOMOUS_ISOLATION` by default.
