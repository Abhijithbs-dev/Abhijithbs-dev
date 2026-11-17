"""Vercel serverless endpoint for SupplyChain Sentinel web scans."""

from __future__ import annotations

import json
import re
import tomllib
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

MAX_BODY = 64 * 1024
MAX_PACKAGES = 100
PIN = re.compile(r"^\\s*([A-Za-z0-9][A-Za-z0-9._-]*)\\s*==\\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)(?:\\s*;.*)?\\s*$")
RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def normalize(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_manifest(raw: str, manifest_format: str):
    dependencies, skipped = [], []
    if manifest_format == "pyproject":
        try:
            data = tomllib.loads(raw)
        except tomllib.TOMLDecodeError as exc:
            raise ValueError(f"Invalid pyproject.toml: {exc}") from exc
        declarations = data.get("project", {}).get("dependencies", [])
        for index, declaration in enumerate(declarations, 1):
            match = PIN.match(declaration)
            if match:
                dependencies.append({"name": normalize(match.group(1)), "version": match.group(2), "source": f"pyproject.toml:project.dependencies[{index}]"})
            else:
                skipped.append(f"project.dependencies[{index}]: not an exact == pin")
    else:
        for line_no, raw_line in enumerate(raw.splitlines(), 1):
            line = raw_line.split("#", 1)[0].strip()
            if not line:
                continue
            if line.startswith(("-r ", "-e ", "--")):
                skipped.append(f"requirements.txt:{line_no}: include, editable or pip option not resolved")
                continue
            match = PIN.match(line)
            if match:
                dependencies.append({"name": normalize(match.group(1)), "version": match.group(2), "source": f"requirements.txt:{line_no}"})
            else:
                skipped.append(f"requirements.txt:{line_no}: not an exact == pin")
    unique = {}
    for dep in dependencies:
        unique[(dep["name"], dep["version"])] = dep
    dependencies = sorted(unique.values(), key=lambda d: (d["name"], d["version"]))
    if len(dependencies) > MAX_PACKAGES:
        raise ValueError(f"Maximum {MAX_PACKAGES} unique pinned packages per scan.")
    if not dependencies:
        raise ValueError("No exact-pinned dependencies found. Use package==version declarations.")
    return dependencies, skipped


def osv_lookup(dependencies):
    payload = {"queries": [{"package": {"name": d["name"], "ecosystem": "PyPI"}, "version": d["version"]} for d in dependencies]}
    request = Request("https://api.osv.dev/v1/querybatch", data=json.dumps(payload).encode(), headers={"Content-Type": "application/json", "Accept": "application/json", "User-Agent": "SupplyChain-Sentinel/0.2"}, method="POST")
    try:
        with urlopen(request, timeout=25) as response:
            result = json.loads(response.read().decode())
    except (HTTPError, URLError, TimeoutError, json.JSONDecodeError) as exc:
        raise RuntimeError(f"OSV lookup failed: {exc}") from exc
    results = result.get("results", [])
    if len(results) != len(dependencies):
        raise RuntimeError("OSV returned an unexpected result count.")
    return results


def get_severity(vulnerability):
    value = str((vulnerability.get("database_specific") or {}).get("severity", "")).upper()
    if value in RANK:
        return "MODERATE" if value == "MEDIUM" else value
    return "UNKNOWN"


def build_response(dependencies, skipped, osv_results):
    findings = []
    for dep, result in zip(dependencies, osv_results):
        for vuln in result.get("vulns", []) or []:
            level = get_severity(vuln)
            refs = [item.get("url") for item in vuln.get("references", []) if item.get("url")]
            details = vuln.get("summary") or (vuln.get("details") or "").split("\\n", 1)[0] or "No summary supplied by the advisory."
            findings.append({
                "package": dep["name"], "version": dep["version"], "ecosystem": "PyPI",
                "id": vuln.get("id", "UNKNOWN-ID"), "aliases": vuln.get("aliases", []) or [],
                "summary": details, "severity": level, "priority": RANK[level],
                "references": refs, "modified": vuln.get("modified"), "source": dep["source"]
            })
    findings.sort(key=lambda f: (-f["priority"], f["package"], f["id"]))
    counts = {level: sum(f["severity"] == level for f in findings) for level in RANK}
    return {
        "tool": {"name": "SupplyChain Sentinel", "version": "0.2.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {"pinned_dependencies": len(dependencies), "skipped_declarations": len(skipped), "vulnerabilities": len(findings), "severity_counts": counts},
        "dependencies": dependencies, "skipped": skipped, "findings": findings
    }


class handler(BaseHTTPRequestHandler):
    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self.path.rstrip("/") != "/api/scan":
            self._send(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY:
                self._send(413, {"error": "Request must be between 1 byte and 64 KB."})
                return
            body = json.loads(self.rfile.read(length))
            if not isinstance(body, dict) or not isinstance(body.get("manifest"), str):
                raise ValueError("Request must include a manifest string.")
            manifest_format = body.get("format", "requirements")
            if manifest_format not in ("requirements", "pyproject"):
                raise ValueError("Unsupported manifest format.")
            dependencies, skipped = parse_manifest(body["manifest"], manifest_format)
            osv_results = osv_lookup(dependencies)
            self._send(200, build_response(dependencies, skipped, osv_results))
        except (ValueError, json.JSONDecodeError) as exc:
            self._send(400, {"error": str(exc)})
        except RuntimeError as exc:
            self._send(502, {"error": str(exc)})
        except Exception:
            self._send(500, {"error": "Unexpected server error. Please retry later."})

    def log_message(self, format, *args):
        return
