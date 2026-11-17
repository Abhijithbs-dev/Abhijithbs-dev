"""Normalize OSV responses and render portable security artifacts."""

from __future__ import annotations

import json
import re
import uuid
from datetime import datetime, timezone


RANK = {"CRITICAL": 4, "HIGH": 3, "MODERATE": 2, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}


def severity(vulnerability: dict) -> str:
    database = vulnerability.get("database_specific", {}) or {}
    value = str(database.get("severity", "")).upper()
    if value in RANK:
        return "MODERATE" if value == "MEDIUM" else value
    for entry in vulnerability.get("severity", []) or []:
        score = entry.get("score", "")
        match = re.search(r"(?:CVSS:3\.[01]/.*?)(?:/|$)", score)
        # OSV commonly supplies a vector, not a base score. Do not invent a numeric score.
        if match:
            return "UNKNOWN"
    return "UNKNOWN"


def build_findings(dependencies: list[dict[str, str]], osv_results: list[list[dict]]) -> list[dict]:
    findings: list[dict] = []
    for dependency, vulnerabilities in zip(dependencies, osv_results):
        for vuln in vulnerabilities:
            aliases = vuln.get("aliases", []) or []
            findings.append({
                "package": dependency["name"],
                "version": dependency["version"],
                "ecosystem": "PyPI",
                "id": vuln.get("id", "UNKNOWN-ID"),
                "aliases": aliases,
                "summary": vuln.get("summary") or vuln.get("details", "").split("\n", 1)[0] or "No summary supplied",
                "severity": severity(vuln),
                "priority": RANK[severity(vuln)],
                "references": [item.get("url") for item in vuln.get("references", []) if item.get("url")],
                "modified": vuln.get("modified"),
                "source": dependency.get("source"),
            })
    return sorted(findings, key=lambda item: (-item["priority"], item["package"], item["id"]))


def json_report(dependencies: list[dict], skipped: list[str], findings: list[dict]) -> str:
    return json.dumps({
        "tool": {"name": "SupplyChain Sentinel", "version": "0.1.0"},
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "pinned_dependencies": len(dependencies),
            "skipped_declarations": len(skipped),
            "vulnerabilities": len(findings),
            "severity_counts": {level: sum(f["severity"] == level for f in findings) for level in RANK},
        },
        "dependencies": dependencies,
        "skipped": skipped,
        "findings": findings,
    }, indent=2)


def sarif_report(findings: list[dict]) -> str:
    rules = {}
    results = []
    for finding in findings:
        rule_id = finding["id"]
        rules.setdefault(rule_id, {
            "id": rule_id,
            "name": finding["package"],
            "shortDescription": {"text": finding["summary"][:300]},
            "helpUri": finding["references"][0] if finding["references"] else "https://osv.dev/",
        })
        level = {"CRITICAL": "error", "HIGH": "error", "MODERATE": "warning", "LOW": "note"}.get(finding["severity"], "none")
        results.append({
            "ruleId": rule_id,
            "level": level,
            "message": {"text": f"{finding['package']} {finding['version']} is affected by {rule_id} (severity: {finding['severity']})."},
            "properties": {"package": finding["package"], "version": finding["version"], "aliases": finding["aliases"]},
        })
    return json.dumps({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {"name": "SupplyChain Sentinel", "rules": list(rules.values())}},
            "results": results,
        }],
    }, indent=2)


def cyclonedx_report(dependencies: list[dict]) -> str:
    components = []
    for dep in dependencies:
        purl = f"pkg:pypi/{dep['name']}@{dep['version']}"
        components.append({
            "type": "library",
            "bom-ref": purl,
            "name": dep["name"],
            "version": dep["version"],
            "purl": purl,
            "scope": "required",
            "properties": [{"name": "sentinel:source", "value": dep.get("source", "")}],
        })
    return json.dumps({
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {"timestamp": datetime.now(timezone.utc).isoformat(), "tools": [{"vendor": "SupplyChain Sentinel", "name": "sentinel", "version": "0.1.0"}]},
        "components": components,
    }, indent=2)
