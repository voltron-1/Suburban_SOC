#!/usr/bin/env python3
"""
verify_detections.py — Issue #22 verifier.

Queries Elasticsearch for the three expected detections from the anomaly
simulation suite and prints a pass/fail summary. Exits non-zero if any
expected detection is missing within the lookback window.

Usage:
    source .env && python3 verify_detections.py
"""

from __future__ import annotations

import os
import sys
from dataclasses import dataclass
from typing import Any

from elasticsearch import Elasticsearch
from elastic_transport import TransportError


@dataclass
class Check:
    name: str
    query: dict[str, Any]
    min_hits: int = 1
    # If set, pass when a single bucket of this term field has >= min_hits docs
    # (e.g. "5+ sessions from one source"), instead of a flat document count.
    agg_field: str | None = None


def build_checks(lookback_min: int) -> list[Check]:
    time_filter = {"range": {"@timestamp": {"gte": f"now-{lookback_min}m"}}}
    return [
        Check(
            name="Port scan  (Scan::Port_Scan in zeek.notice)",
            query={
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "zeek.notice"}},
                        {"match_phrase": {"note": "Scan::Port_Scan"}},
                    ],
                    "filter": time_filter,
                }
            },
        ),
        Check(
            # Volume-based: 5+ SSH sessions from one source in the window. Zeek's
            # per-connection auth_success inference is unreliable over loopback
            # (large-MTU, unsegmented packets defeat its packet-size heuristic, so
            # auth_attempts stays 0), so we key on the brute-force *cadence* — the
            # same signal Zeek's own detect-bruteforcing policy uses.
            name="SSH brute force  (5+ zeek.ssh sessions from one source)",
            min_hits=5,
            agg_field="id.orig_h.keyword",
            query={
                "bool": {
                    "must": [{"match": {"event.dataset": "zeek.ssh"}}],
                    "filter": time_filter,
                }
            },
        ),
        Check(
            name="Malware download (application/zip in zeek.files)",
            query={
                "bool": {
                    "must": [
                        {"match": {"event.dataset": "zeek.files"}},
                        {"match_phrase": {"mime_type": "application/zip"}},
                    ],
                    "filter": time_filter,
                }
            },
        ),
    ]


def main() -> int:
    es_url = os.environ.get("ES_URL", "http://localhost:9200")
    index = os.environ.get("ES_INDEX", "logstash-security-*")
    lookback = int(os.environ.get("LOOKBACK_MIN", "10"))
    user = os.environ.get("ES_USER") or None
    password = os.environ.get("ES_PASS") or None

    kwargs: dict[str, Any] = {"hosts": [es_url]}
    if user and password:
        kwargs["basic_auth"] = (user, password)

    es = Elasticsearch(**kwargs)

    print(f"[*] Elasticsearch: {es_url}")
    print(f"[*] Index pattern: {index}")
    print(f"[*] Lookback:      now-{lookback}m\n")

    failures = 0
    for check in build_checks(lookback):
        try:
            if check.agg_field:
                # Bucket by the term field; "hits" = the largest single bucket,
                # i.e. the most sessions attributable to one source.
                resp = es.search(
                    index=index,
                    size=0,
                    query=check.query,
                    aggs={"by_src": {"terms": {"field": check.agg_field, "size": 10}}},
                )
                buckets = resp["aggregations"]["by_src"]["buckets"]
                hits = max((b["doc_count"] for b in buckets), default=0)
            else:
                resp = es.count(index=index, query=check.query)
                hits = resp.get("count", 0)
        except TransportError as exc:
            print(f"  [ERR ] {check.name} — Elasticsearch unreachable: {exc}")
            return 2
        ok = hits >= check.min_hits
        marker = "PASS" if ok else "FAIL"
        print(f"  [{marker}] {check.name} — hits={hits} (need >= {check.min_hits})")
        if not ok:
            failures += 1

    print()
    if failures:
        print(f"[-] {failures} detection(s) missing. Re-run sims or widen LOOKBACK_MIN.")
        return 1
    print("[+] All expected detections present.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
