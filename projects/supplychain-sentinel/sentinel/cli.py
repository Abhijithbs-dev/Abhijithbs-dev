"""Command-line entry point."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from sentinel.osv import OSVError, query_vulnerabilities
from sentinel.parser import discover_dependencies
from sentinel.report import build_findings, cyclonedx_report, json_report, sarif_report


def run_scan(target: Path, output_format: str) -> str:
    dependencies, skipped = discover_dependencies(target)
    osv_results = query_vulnerabilities([dep.as_dict() for dep in dependencies])
    findings = build_findings([dep.as_dict() for dep in dependencies], osv_results)
    if output_format == "sarif":
        return sarif_report(findings)
    if output_format == "cyclonedx":
        return cyclonedx_report([dep.as_dict() for dep in dependencies])
    return json_report([dep.as_dict() for dep in dependencies], skipped, findings)


def main() -> int:
    parser = argparse.ArgumentParser(prog="sentinel", description="Scan pinned Python dependencies against OSV.")
    subparsers = parser.add_subparsers(dest="command", required=True)
    scan = subparsers.add_parser("scan", help="scan a requirements.txt, pyproject.toml, or project directory")
    scan.add_argument("target", type=Path)
    scan.add_argument("--format", choices=("json", "sarif", "cyclonedx"), default="json")
    scan.add_argument("--output", type=Path, help="write report to a file instead of stdout")
    args = parser.parse_args()

    try:
        report = run_scan(args.target, args.format)
    except (OSError, ValueError, OSVError) as exc:
        print(f"sentinel: error: {exc}", file=sys.stderr)
        return 2

    if args.output:
        args.output.write_text(report + "\n", encoding="utf-8")
        print(f"Report written to {args.output}")
    else:
        print(report)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
