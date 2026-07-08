# Findings — #160 / #161 Logstash ECS normalization + source geoip

Date: 2026-07-07
Scope: `configs/logstash.conf` (ingest pipeline)
Branch to open off `main` at commit time (currently on stale merged `fix/ingest-lag-slo-recovery`).

## Summary

Both issues are SOP-147 dashboard-validation leftovers: Network/Endpoint panels render
"No results" because the Logstash pipeline never produces the ECS fields the panels query.
Root cause verified by config inspection (ES unreachable locally — stack down, needs sudo
restart per the ingest-pipeline-restart runbook).

Key structural fact: **Filebeat-shipped Zeek logs arrive tagged `endpoint_logs` and are
handled in the "Category 0" block (`configs/logstash.conf:50`), NOT the `network_logs`
branch.** The `network_logs` branch already had the TLS renames — but real Zeek data never
reaches it. That is why #160's panels were empty despite the mapping "existing."

## #160 — zeek.ssl SNI/cipher not ECS-normalized

- Root cause: Category 0 renamed conn/dns/http fields to ECS but had **no**
  `server_name`/`cipher` → `tls.*` mapping. Panels query `tls.client.server_name.keyword`
  / `tls.cipher.keyword`.
- Fix (`configs/logstash.conf`, zeek.ssl block): scoped `if [event][dataset] == "zeek.ssl"`
  mutate renaming `server_name`→`tls.client.server_name`, `cipher`→`tls.cipher`,
  `curve`→`tls.curve`, `version`→`tls.version`, `validation_status`→`tls.validation_status`.
  Scoped to `zeek.ssl` so the generic `version` key cannot collide with the zeek.software
  `version` handling above it (confirmed mutually exclusive — dataset set once at Cat-0 top).

## #161 — geoip destination-only → source.geo empty (Failed SSH by Country)

The issue named ONE blocker (geoip). Investigation found **three**, all of which had to be
fixed for the panel (query `event.outcome:failure`, bucket `source.geo.country_name`) to
render:

1. **Flat-dotted grok (the real root cause).** auth.log grok captured `%{IP:source.ip}` — a
   *flat* key. The pipeline's own NOTE (`configs/logstash.conf:163`) documents that
   `if [source][ip]` (nested) never matches a flat `source.ip`, so the issue's proposed
   "just add a geoip filter" would have silently done nothing. Fixed: full ECS bracket
   notation.
2. **event.outcome mismatch.** grok yielded `event.outcome="Failed"`; panel queries
   `failure`. Never matched. Fixed: normalize `Failed`→`failure`, `Accepted`→`success`.
3. **invalid-user lines dropped.** `%{USER}` stopped at "invalid" in
   `Failed password for invalid user <x> from <ip>` — the bulk of attacker traffic — so grok
   failed the whole line. Fixed: `(?:invalid user )?` prefix + greedy username.

Then: guarded geoip on `[source][ip]` (skips RFC1918/loopback/link-local/ULA, identical
guard to the Cat-0 zeek branch).

## Parallel review (code-reviewer + security-auditor) — findings & resolution

| Sev | Finding | Resolution |
|-----|---------|-----------|
| **HIGH** | **source.ip spoof.** Username is attacker-controlled and echoed *before* the sshd-appended client IP. Non-greedy `%{DATA}` bound `[source][ip]` to an injected `from <ip> port <n>` inside the username → forge country attribution, inject RFC1918 to evade geoip guard, poison HUNT-002. (Regression I introduced by moving `%{USER}`→`%{DATA}`.) | **Fixed:** fully anchored `^…$` grok + **greedy** username so the trailing sshd-supplied IP is always the last match and always wins. Proven with 7 offline cases incl. 3 spoof variants — real IP wins every time. |
| MED | Grok backtracking / ingest-lag risk over non-sshd auth.log lines (sudo/cron/PAM all fail the pattern). | **Fixed:** cheap `"sshd[" in [message]` pre-filter keeps non-sshd lines out of the engine; full anchoring bounds backtracking; `timeout_millis => 1000` caps worst case. |
| MED | Secret/PII leak: attacker `[user][name]` (may contain pasted creds) bypassed the message-only redaction gsub → persisted to ES/snapshots past right-to-erasure (SOP-012). | **Fixed:** extended the credential gsub to also redact `[user][name]`. |
| MED | code-reviewer: `keyboard-interactive/pam` method unmatched by `%{WORD}`. | **Fixed:** `%{NOTSPACE}` for the auth method. |
| LOW | geoip guard misses `::ffff:` IPv4-mapped-IPv6; guard regex duplicated 3×. | **Deferred** (HIGH fix removes attacker control over which IP is evaluated). |
| Cov | Standalone `Invalid user <x> from <ip>` line (no verb) not matched; numeric fields land as keyword not `long`; add `tls.*`/`process.pid` to index template. | **Deferred to follow-up issue.** |

## Purple-team coverage (T1110 Brute Force) — post-fix

| Attacker action | Pre-fix | Post-fix |
|---|---|---|
| Brute force valid user from public IP | source.geo empty (flat grok + no geoip) | attributed by country ✓ |
| Brute force invalid user (bulk of traffic) | line dropped entirely | parsed + attributed ✓ |
| Spoof `user=x from 8.8.8.8 port 22` | would forge source.ip | real trailing IP wins ✓ |
| Inject RFC1918 to skip geoip | would evade panel | real public IP wins → enriched ✓ |
| Paste credential as username | leaked verbatim to ES | redacted ✓ |

## Verification status

- Config: brace-balanced (depth 0), single `timeout_millis`, constructs present.
- Grok behavior: proven offline (Python regex equivalents) — all legit + spoof cases.
- **NOT yet verified live:** panels rendering + `source.geo`/`tls.*` populated on real docs —
  requires the stack up (ES down locally; sudo restart per runbook). Forward-config only;
  historical docs need rollover/reindex once the stack is up. Do NOT claim panels render
  until confirmed against live Kibana.

## Operational follow-ups (need stack up)

1. `logstash --config.test_and_exit -f configs/logstash.conf` (live syntax parse).
2. Rollover `logstash-security-*` data stream; confirm new zeek.ssl docs carry `tls.*` and
   new auth.log docs carry `source.geo.*`.
3. Open Network + Endpoint dashboards; confirm SNI / Cipher / Failed SSH by Country render.
4. File follow-up issue for the deferred coverage items above.
