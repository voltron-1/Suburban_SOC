#!/usr/bin/env python3
# =============================================================================
# es_client.py — single source of truth for the Python side of the ES/Kibana
# HTTP client (issue #170; bash side is es_common.sh). Every raw-`requests`
# script (slo_metrics.py, run_hunts.py) previously opened a brand-new
# TCP+TLS connection per call with no retry — get_session() returns one
# pooled, retrying requests.Session instead.
#
# Usage:
#   import es_client
#   SESSION = es_client.get_session(ES_USER, ES_PASS)
#   SESSION.request("POST", f"{ES_URL}/idx/_search", verify=ES_VERIFY, ...)
#
# Credentials and TLS verification stay the caller's responsibility (ES_URL/
# ES_CA vary per script and per call target — e.g. slo_metrics.py also calls
# Kibana on a separate host); this module only owns connection pooling and
# the retry policy, not credential resolution.
#
# Retry policy: connection failures (pre-send, always safe) and 502/503/504
# (the server explicitly did not process the request, always safe) are
# retried with backoff. read=0 deliberately disables retry-after-read-timeout:
# if a write (e.g. a bulk index) times out waiting for the response, the
# server may have already applied it, and retrying could double-write.
# =============================================================================
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


def get_session(user, password, retries=3, backoff_factor=0.5):
    session = requests.Session()
    session.auth = (user, password)
    retry = Retry(
        total=retries,
        connect=retries,
        status=retries,
        read=0,
        backoff_factor=backoff_factor,
        status_forcelist=(502, 503, 504),
        allowed_methods=frozenset(["GET", "POST", "PUT"]),
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("https://", adapter)
    session.mount("http://", adapter)
    return session
