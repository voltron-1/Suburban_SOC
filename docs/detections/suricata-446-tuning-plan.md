# Suricata starter set — finishing the last 20 rules (#446)

**Status date:** 2026-10-24. Source of the numbers: `docs/detections/suricata-starter-set.md`
("What is still NOT done") and `rules/suricata/*.rules`. 80 of 100 rules are enabled; these 20 are not.

**Nothing here has been run against live traffic.** This repo's records show no live Suricata alert,
and `planned_execution.md` recorded the repo's own `suricata-host-capture.service` as not installed
(2026-09-07). `CLAUDE.md` says a `suricata.service` is active on the capture host, so a Suricata may already be
running under a different unit; step 1 checks. Everything below is a plan plus tooling tested on synthetic data only.

## The 20 rules, by what blocks each

| Group | SIDs | Blocker | Who can unblock |
|---|---|---|---|
| A. Threshold tuning (14) | 9000001, 9000002, 9000005, 9000008, 9000009, 9000010, 9000046, 9000060, 9000062, 9000073, 9000080, 9000082, 9000083, 9000100 | `detection_filter` `count`/`seconds` are the starter set's illustrative defaults, never measured here | Baseline traffic + a reviewer (steps 1–6) |
| B. Unresolved placeholders (2) | 9000013 (look-alike domain), 9000099 (`iotbotnet` C2 domain) | Needs a real value; this repo does not invent IOCs | Owner |
| C. DLP sign-off (2) | 9000065 (`STU\d{7}` student ID), 9000066 (card number pattern) | Data-handling policy owner must approve scanning payloads for these | Owner |
| D. Dead as configured (2) | 9000063 (mega.nz), 9000064 (Dropbox) | Need `>1MB` request bodies; `configs/suricata/suricata.yaml` has `request-body-limit: 100kb` | Owner decision (below) |

Note 9000065 is in both B and C.

## Group A — threshold tuning, in order

Each step has a "done when". Steps 1–3 need the capture host; the tooling is
`scripts/setup/suricata_threshold_baseline.py` (tests: `tests/setup/test_suricata_threshold_baseline.py`).

1. **Confirm the sensor.** Run `systemctl list-units '*suricata*'` and note which unit is active and which
   `suricata.yaml` it loads. If it is not the repo's `configs/suricata/suricata.yaml`, install the repo's unit with
   `sudo bash scripts/setup/redeploy_systemd_units.sh`. *Done when:* `eve.json` is growing with the repo's config and Zeek
   is still writing `conn.log` (the two share a host; #443 flagged CPU/memory risk).
2. **Build the baseline rules.** `python3 scripts/setup/suricata_threshold_baseline.py prepare --out /var/tmp/baseline.rules`.
   This writes the 14 rules enabled with `detection_filter` removed. It refuses to write inside `rules/suricata/`.
   Never list this file in `rule-files:`. *Done when:* the file has 14 `alert` lines and `suricata -T -S /var/tmp/baseline.rules -c configs/suricata/suricata.yaml` passes (CI runs that check).
3. **Collect at least 7 days of ordinary traffic** through a separate, alert-only Suricata run that loads only
   `baseline.rules` and writes to its own log directory (for example `-l /var/log/suricata-baseline`), or
   replay stored pcaps with `suricata -r <pcap> -S baseline.rules -l <dir>`. *This exact invocation has not been run;
   check interface, `cluster-id` and pidfile do not collide with the production instance.* Expect one alert per
   matching packet, so watch disk. *Done when:* the baseline `eve.json` spans 7+ days. The operator must confirm
   the period contained no attack, or the thresholds will be raised to hide one.
4. **Analyse.** `python3 scripts/setup/suricata_threshold_baseline.py analyze --eve <baseline eve.json> --format table`.
   For each rule it reports the busiest key's matches inside the rule's window, how many keys would have
   reached the shipped count, and a suggested count (`ceil(max × 1.25) + 1`, never below the shipped count).
   It marks the run `PROVISIONAL` when the span is under 7 days. A rule with no matching traffic is reported
   as **untested**, not safe. *Done when:* a reviewer has read every row.
5. **Decide and edit.** A reviewer sets each `count`/`seconds` in the `.rules` file and records the baseline numbers
   in the rule file's header comment. *Done when:* the PR shows the baseline row next to each changed value.
6. **Write fixtures, then enable in batches of 3–4.** The CI promotion gate
   (`tests/detections/suricata_rules_eval.py`) refuses an enabled rule without a passing true-positive pcap
   fixture, and **none of the 14 has one**. A threshold rule's TP fixture must exceed the tuned `count` inside
   `seconds`, and its TN fixture must stay under it, so write fixtures after step 5 and regenerate them whenever a
   threshold changes. After each batch, run the replay harness and watch live alerts for a day before the next.
   *Done when:* the rule is enabled, its fixtures pass in CI, and a day of live alerts has been reviewed.

## Groups B, C, D — decisions that are the owner's

1. **9000013 and 9000099 (placeholders).** Supply the real domain/IOC, or remove the rule. A second question, noted
   as an observation not a finding: these rules, and others in the set (CAS SSO login, MFA push, FERPA student IDs,
   LDAP), are written for a university. `HOME_NET` here is `10.18.81.0/24` and `192.168.1.0/24`, and the README
   describes a residential mesh. Some of the 20 may not apply to this deployment at all; deleting them is a valid answer.
2. **9000065 and 9000066 (DLP).** Approve or decline payload scanning for student-ID and card-number patterns.
   If declined, delete the rules; do not leave them as dormant comments.
3. **9000063 and 9000064 (`>1MB` upload rules).** Options: (a) raise `request-body-limit` in
   `configs/suricata/suricata.yaml`; the per-flow memory cost is unmeasured, so decide it with the load-test numbers from
   production-plan item 4; (b) rewrite the rules to use flow byte counters instead of body inspection; (c) remove them.
   There is no recommendation here because none of the three has been tested.

## What this PR does not do

It enables no rule, changes no threshold, and adds no fixture. It does not touch #443 or #444, which stay open.

**Issue status:** #446 itself was closed on 2026-10-17 by owner decision, with 80 of 100 rules enabled (see the M23 row in `README.md`). These 20 rules therefore have **no open tracking issue**. File one in milestone M23 (milestone/28) if this work should be tracked.
