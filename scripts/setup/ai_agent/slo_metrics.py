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


def es(method, path, body=None):
    return requests.request(
        method, f"{ES_URL}{path}", auth=(ES_USER, ES_PASS), verify=False,
        headers={"Content-Type": "application/json"},
        data=json.dumps(body) if body is not None else None, timeout=15)


def kb(path):
    return requests.get(f"{KIBANA_URL}{path}", auth=(ES_USER, ES_PASS),
                        headers={"kbn-xsrf": "true"}, timeout=15)


def _count(index, query):
    try:
        r = es("POST", f"/{index}/_count", {"query": query})
        return r.json().get("count", 0) if r.status_code == 200 else 0
    except Exception:
        return 0


def metric_mttd():
    """Mean detect latency (min): alert creation time minus the source event time."""
    body = {"size": 500, "sort": [{"@timestamp": "desc"}],
            "_source": ["@timestamp", "kibana.alert.original_time", "kibana.alert.start"],
            "query": {"range": {"@timestamp": {"gte": WINDOW}}}}
    try:
        r = es("POST", "/.alerts-security.alerts-*/_search", body)
        hits = r.json().get("hits", {}).get("hits", [])
    except Exception:
        hits = []
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
            continue
    return round(sum(deltas) / len(deltas), 2) if deltas else None


def metric_mttr():
    """Mean automated response latency (min) from soar-actions.response.latency_seconds."""
    body = {"size": 0, "query": {"bool": {"filter": [
        {"range": {"@timestamp": {"gte": WINDOW}}},
        {"exists": {"field": "response.latency_seconds"}}]}},
        "aggs": {"avg_lat": {"avg": {"field": "response.latency_seconds"}}}}
    try:
        r = es("POST", "/soar-actions-*/_search", body)
        v = r.json().get("aggregations", {}).get("avg_lat", {}).get("value")
        return round(v / 60.0, 3) if v is not None else None
    except Exception:
        return None


def metric_coverage():
    p = REPO / "docs" / "detections" / "attack-coverage.json"
    try:
        return float(len(json.loads(p.read_text(encoding="utf-8")).get("techniques", [])))
    except Exception:
        return None


def metric_false_positive_pct():
    """% of closed cases dispositioned false_positive."""
    try:
        total = kb("/api/cases/_find?perPage=1&status=closed").json().get("total", 0)
        fp = kb("/api/cases/_find?perPage=1&status=closed&tags=disposition:false_positive"
                ).json().get("total", 0)
        return round(100.0 * fp / total, 2) if total else 0.0
    except Exception:
        return None


def metric_ingest_lag_seconds():
    body = {"size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["@timestamp"]}
    try:
        hits = es("POST", "/logstash-security-*/_search", body).json().get("hits", {}).get("hits", [])
        if not hits:
            return None
        newest = datetime.fromisoformat(hits[0]["_source"]["@timestamp"].replace("Z", "+00:00"))
        return round((datetime.now(timezone.utc) - newest).total_seconds(), 1)
    except Exception:
        return None


def metric_parse_error_pct():
    win = {"range": {"@timestamp": {"gte": WINDOW}}}
    total = _count("logstash-security-*", win)
    errs = _count("logstash-security-*", {"bool": {"filter": [win, {"term": {"pipeline.error": "true"}}]}})
    return round(100.0 * errs / total, 3) if total else 0.0


def main():
    if not ES_PASS:
        print("ERROR: ES_PASS / ELASTIC_PASSWORD required", file=sys.stderr)
        sys.exit(1)
    values = {
        "mttd_minutes": metric_mttd(),
        "mttr_minutes": metric_mttr(),
        "coverage_techniques": metric_coverage(),
        "false_positive_pct": metric_false_positive_pct(),
        "ingest_lag_seconds": metric_ingest_lag_seconds(),
        "parse_error_pct": metric_parse_error_pct(),
    }
    now = datetime.now(timezone.utc).isoformat()
    doc = {"@timestamp": now, "slo": {}}
    breaches = []
    print(f"SOC SLO metrics @ {now}")
    print(f"  {'metric'.ljust(20)} {'value':>10}  {'target':>8}  status")
    for name, val in values.items():
        target = TARGETS[name]
        lower = LOWER_BETTER[name]
        if val is None:
            status, breach = "n/a", False
        else:
            breach = (val > target) if lower else (val < target)
            status = "BREACH" if breach else "ok"
        if breach:
            breaches.append(name)
        doc["slo"][name] = {"value": val, "target": target,
                            "comparator": "<=" if lower else ">=", "breach": breach}
        print(f"  {name.ljust(20)} {str(val):>10}  {('<=' if lower else '>=')+str(target):>8}  {status}")
    doc["breach_count"] = len(breaches)
    doc["status"] = "breach" if breaches else "ok"

    # Index for the SLO dashboard.
    try:
        es("POST", "/soc-slo-metrics/_doc", doc)
        print(f"  -> indexed to soc-slo-metrics (breaches: {len(breaches)})")
    except Exception as e:
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

    sys.exit(2 if breaches else 0)


if __name__ == "__main__":
    main()
