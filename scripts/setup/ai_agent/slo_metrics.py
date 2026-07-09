#!/usr/bin/env python3
# =============================================================================
# slo_metrics.py — WS2.4: self-measuring SOC metrics & SLOs.
#
# Computes the SOC's own performance metrics against defined targets, indexes them
# to the `soc-slo-metrics` index (for the SLO dashboard), and raises an ntfy alert
# if any SLO is breached. Run on a schedule (cron) alongside refresh_intel.sh.
#
#   MTTD  (mean time to detect)      <= 30 min   — detection-engine alerts
#   MTTR  (automated response)       <= 5  min   — soar-actions response.latency_seconds
#   Detection coverage               >= 10 tech  — docs/detections/attack-coverage.json
#   False-positive rate              <= 10 %     — Kibana cases disposition tags
#   Ingest lag                       <= 300 s    — newest logstash-security event age
#   Parse-error (drop) rate          <= 1  %     — pipeline.error over the window
#
# Pure stdlib (requests). Env (auto-loaded from scripts/setup/.env):
#   ES_URL, ES_USER, ES_PASS/ELASTIC_PASSWORD, KIBANA_URL, NTFY_TOPIC.
# Targets overridable via SLO_<NAME> env (e.g. SLO_MTTD_MAX_MIN=20).
# =============================================================================
import json
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
ENV = REPO / "scripts" / "setup" / ".env"
if ENV.exists():
    for line in ENV.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            os.environ.setdefault(k, v)

ES_URL = os.environ.get("ES_URL", "https://localhost:9200")
ES_USER = os.environ.get("ES_USER", "elastic")
ES_PASS = os.environ.get("ES_PASS") or os.environ.get("ELASTIC_PASSWORD", "")
KIBANA_URL = os.environ.get("KIBANA_URL", "http://localhost:5601")
NTFY_TOPIC = os.environ.get("NTFY_TOPIC", "")
WINDOW = os.environ.get("SLO_WINDOW", "now-7d")

TARGETS = {
    "mttd_minutes":        float(os.environ.get("SLO_MTTD_MAX_MIN", "30")),
    "mttr_minutes":        float(os.environ.get("SLO_MTTR_MAX_MIN", "5")),
    "coverage_techniques": float(os.environ.get("SLO_COVERAGE_MIN", "10")),
    "false_positive_pct":  float(os.environ.get("SLO_FP_MAX_PCT", "10")),
    "ingest_lag_seconds":  float(os.environ.get("SLO_INGEST_LAG_MAX_S", "300")),
    "parse_error_pct":     float(os.environ.get("SLO_PARSE_ERR_MAX_PCT", "1")),
}
# Comparator per metric: True = lower is better (value <= target).
LOWER_BETTER = {
    "mttd_minutes": True, "mttr_minutes": True, "coverage_techniques": False,
    "false_positive_pct": True, "ingest_lag_seconds": True, "parse_error_pct": True,
}
# Fail closed: for these metrics an unmeasurable value (None) is itself a breach,
# not a benign "n/a". A dead/unreachable pipeline produces no fresh docs, so
# metric_ingest_lag_seconds() returns None — the single loudest failure must alarm,
# not register as silence. (WS2.4 observability gap: a total ingest outage was being
# scored breach=False because lag could not be read.)
BREACH_IF_NA = {"ingest_lag_seconds"}


# FAIL CLOSED (audit P1-2): verify TLS against the stack CA instead of verify=False.
# ES_CA defaults to the agent container's mounted CA; set it to your CA path for
# host/standalone runs, or to "" to verify against the system trust store. requests
# raises a clear error if the path is missing — we never silently skip verification.
ES_CA = os.environ.get("ES_CA", "/certs/ca/ca.crt")
ES_VERIFY = ES_CA if ES_CA else True


class MetricUnavailable(Exception):
    """Raised when a metric could not be measured because the ES/Kibana request
    failed (or, for metric_coverage, the local file couldn't be read) — distinct
    from a legitimate empty/zero result (audit #165 / NIST SI-11). A down or
    unreachable dependency must never be reported as a benign 'n/a'."""


def es(method, path, body=None):
    return requests.request(
        method, f"{ES_URL}{path}", auth=(ES_USER, ES_PASS), verify=ES_VERIFY,
        headers={"Content-Type": "application/json"},
        data=json.dumps(body) if body is not None else None, timeout=15)


def kb(path):
    return requests.get(f"{KIBANA_URL}{path}", auth=(ES_USER, ES_PASS),
                        headers={"kbn-xsrf": "true"}, timeout=15)


def _count(index, query):
    try:
        r = es("POST", f"/{index}/_count", {"query": query})
        if r.status_code != 200:
            raise MetricUnavailable(f"{index} count returned HTTP {r.status_code}")
        return r.json().get("count", 0)
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"{index} count request failed: {e}") from e


def metric_mttd():
    """Mean detect latency (min): alert creation time minus the source event time."""
    body = {"size": 500, "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "kibana.alert.original_time", "kibana.alert.start"],
            "query": {"range": {"@timestamp": {"gte": WINDOW}}}}
    try:
        r = es("POST", "/.alerts-security.alerts-*/_search", body)
        if r.status_code != 200:
            raise MetricUnavailable(f"mttd search returned HTTP {r.status_code}")
        hits = r.json().get("hits", {}).get("hits", [])
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"mttd search failed: {e}") from e
    deltas = []
    for h in hits:
        s = h.get("_source", {})
        start = s.get("kibana.alert.start") or s.get("@timestamp")
        orig = s.get("kibana.alert.original_time") or s.get("@timestamp")
        try:
            a = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
            b = datetime.fromisoformat(str(orig).replace("Z", "+00:00"))
            d = (a - b).total_seconds() / 60.0
            if d >= 0:
                deltas.append(d)
        except Exception:
            continue  # a single malformed hit is skipped — not a measurement error
    return round(sum(deltas) / len(deltas), 2) if deltas else None


def metric_mttr():
    """Mean automated response latency (min) from soar-actions.response.latency_seconds."""
    body = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": WINDOW}}},
        {"exists": {"field": "response.latency_seconds"}}]}},
        "aggs": {"avg_lat": {"avg": {"field": "response.latency_seconds"}}}}
    try:
        r = es("POST", "/soar-actions-*/_search", body)
        if r.status_code != 200:
            raise MetricUnavailable(f"mttr search returned HTTP {r.status_code}")
        v = r.json().get("aggregations", {}).get("avg_lat", {}).get("value")
        return round(v / 60.0, 3) if v is not None else None
    except MetricUnavailable:
        raise
    except Exception as e:
        raise MetricUnavailable(f"mttr search failed: {e}") from e


def metric_coverage():
    p = REPO / "docs" / "detections" / "attack-coverage.json"
    try:
        return float(len(json.loads(p.read_text(encoding="utf-8")).get("techniques", [])))
    except Exception as e:
        raise MetricUnavailable(f"attack-coverage.json unreadable: {e}") from e


def metric_false_positive_pct():
    """% of closed cases dispositioned false_positive."""
    try:
        total = kb("/api/cases/_find?perPage=1&status=closed").json().get("total", 0)
        fp = kb("/api/cases/_find?perPage=1&status=closed&tags=disposition:false_positive"
                ).json().get("total", 0)
        return round(100.0 * fp / total, 2) if total else 0.0
    except Exception as e:
        raise MetricUnavailable(f"cases query failed: {e}") from e


def metric_ingest_lag_seconds():
    body = {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp"]}
    try:
        hits = es("POST", "/logstash-security-*/_search", body).json().get("hits", {}).get("hits", [])
        if not hits:
            return None
        newest = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
        return round((datetime.now(timezone.utc) - newest).total_seconds(), 1)
    except Exception as e:
        raise MetricUnavailable(f"ingest-lag search failed: {e}") from e


def metric_parse_error_pct():
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    total = _count("logstash-security-*", win)
    errs = _count("logstash-security-*", {"bool": {"filter": [win, {"term": {"pipeline.error": "true"}}]}})
    return round(100.0 * errs / total, 3) if total else 0.0


def main():
    if not ES_PASS:
        print("ERROR: ES_PASS / ELASTIC_PASSWORD required", file=sys.stderr)
        sys.exit(1)

    metric_fns = {
        "mttd_minutes": metric_mttd,
        "mttr_minutes": metric_mttr,
        "coverage_techniques": metric_coverage,
        "false_positive_pct": metric_false_positive_pct,
        "ingest_lag_seconds": metric_ingest_lag_seconds,
        "parse_error_pct": metric_parse_error_pct,
    }
    values, errors = {}, {}
    for name, fn in metric_fns.items():
        try:
            values[name] = fn()
        except MetricUnavailable as e:
            # audit #165 / NIST SI-11: a measurement failure must never look
            # like a benign "n/a" or a healthy "0" — it is always a breach.
            values[name] = None
            errors[name] = str(e)

    now = datetime.now(timezone.utc).isoformat()
    doc = {"@timestamp": now, "slo": {}}
    breaches = []
    print(f"SOC SLO metrics @ {now}")
    print(f"  {'metric'.ljust(20)} {'value':>10}  {'target':>8}  status")
    for name, val in values.items():
        target = TARGETS[name]
        lower = LOWER_BETTER[name]
        if name in errors:
            breach = True
            status = "ERROR(unmeasurable)"
        elif val is None:
            # Fail closed for liveness-critical metrics: unmeasurable == breach.
            breach = name in BREACH_IF_NA
            status = "BREACH(no-data)" if breach else "n/a"
        else:
            breach = (val > target) if lower else (val < target)
            status = "BREACH" if breach else "ok"
        if breach:
            breaches.append(name)
        entry = {"value": val, "target": target,
                 "comparator": "<=" if lower else ">=", "breach": breach}
        if name in errors:
            entry["error"] = errors[name]
        doc["slo"][name] = entry
        print(f"  {name.ljust(20)} {str(val):>10}  {('<=' if lower else '>=')+str(target):>8}  {status}")
    doc["breach_count"] = len(breaches)
    doc["status"] = "breach" if breaches else "ok"

    # Index for the SLO dashboard.
    index_failed = False
    try:
        es("POST", "/soc-slo-metrics/_doc", doc)
        print(f"  -> indexed to soc-slo-metrics (breaches: {len(breaches)})")
    except Exception as e:
        index_failed = True
        print(f"  -> ES index failed: {e}", file=sys.stderr)

    # Alert on breach (best-effort).
    if breaches and NTFY_TOPIC:
        try:
            requests.post(f"https://ntfy.sh/{NTFY_TOPIC}",
                          data=f"SOC SLO BREACH: {', '.join(breaches)}".encode(),
                          headers={"Title": "Suburban-SOC SLO breach", "Priority": "high",
                                   "Tags": "chart_with_downwards_trend,warning"}, timeout=8)
        except Exception:
            pass

    # audit #165 / NIST SI-11: a measurement error (or a failure to persist the
    # doc at all) is a harder failure than a routine target breach — exit 3 so
    # slo-metrics.service (SuccessExitStatus=0 2) correctly reports a failed
    # run instead of blending it into "successful run, breach".
    if errors or index_failed:
        sys.exit(3)
    sys.exit(2 if breaches else 0)


if __name__ == "__main__":
    main()
