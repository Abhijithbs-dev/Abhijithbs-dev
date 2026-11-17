"""Minimal client for the public OSV batch query API."""

from __future__ import annotations

import json
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

OSV_QUERYBATCH = "https://api.osv.dev/v1/querybatch"


class OSVError(RuntimeError):
    """Raised when the OSV service cannot be queried."""


def query_vulnerabilities(dependencies: list[dict[str, str]]) -> list[list[dict]]:
    if not dependencies:
        return []
    payload = {
        "queries": [
            {"package": {"name": dep["name"], "ecosystem": "PyPI"}, "version": dep["version"]}
            for dep in dependencies
        ]
    }
    request = Request(
        OSV_QUERYBATCH,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=20) as response:
            result = json.loads(response.read().decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise OSVError(f"OSV query failed: {exc}") from exc
    results = result.get("results", [])
    if len(results) != len(dependencies):
        raise OSVError("OSV returned an unexpected number of query results")
    return [item.get("vulns", []) for item in results]
