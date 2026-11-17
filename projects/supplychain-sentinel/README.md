# SupplyChain Sentinel

<p align="center">
  <img src="https://img.shields.io/badge/DevSecOps-dependency%20risk-7c3aed?style=for-the-badge" alt="DevSecOps dependency risk">
  <img src="https://img.shields.io/badge/Python-3.11%2B-3776ab?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+">
  <img src="https://img.shields.io/badge/Output-SARIF%20%7C%20CycloneDX-0f766e?style=for-the-badge" alt="SARIF and CycloneDX output">
</p>

**A lightweight, explainable dependency-risk scanner for Python projects.** It inventories pinned dependencies, checks them against the [OSV vulnerability database](https://osv.dev/), prioritizes findings, and exports machine-readable security artifacts.

> Portfolio project in active development. This initial release is a focused MVP, not a replacement for a full SCA platform or a security audit.

## Why this problem matters

OWASP Top 10:2025 identifies **A03: Software Supply Chain Failures** as a major application-security risk. Modern applications inherit risk through direct and transitive dependencies, build tooling, and update channels. Small teams and student projects often lack a repeatable, understandable way to review dependency risk.

SupplyChain Sentinel addresses one tractable part of that problem: **known vulnerabilities in pinned Python dependencies**, with transparent evidence and portable reports.

## What it does

- Reads pinned dependencies from `requirements.txt` and PEP 621 `pyproject.toml`.
- Queries the OSV API in batches (no API key required).
- Maps OSV severity metadata to an easy-to-triage priority.
- Generates a CycloneDX 1.5 JSON SBOM.
- Exports findings as JSON or SARIF 2.1.0 for code-scanning workflows.
- Reports unpinned or unsupported dependency declarations rather than silently treating them as safe.

## Quick start

Requires Python 3.11+.

```bash
git clone https://github.com/Abhijithbs-dev/Abhijithbs-dev.git
cd Abhijithbs-dev/projects/supplychain-sentinel
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\\Scripts\\activate
pip install -e .
```

Scan a project directory:

```bash
sentinel scan /path/to/python-project
```

Or run from source:

```bash
python -m sentinel.cli scan /path/to/python-project --format json
python -m sentinel.cli scan /path/to/python-project --format sarif --output results.sarif
python -m sentinel.cli scan /path/to/python-project --format cyclonedx --output sbom.cdx.json
```

The scanner looks for `requirements.txt` and `pyproject.toml` in the supplied directory. You can also pass a single supported file.

## Example output

```text
SupplyChain Sentinel
Target: ./sample-app
Dependencies: 8 pinned | 2 declarations skipped
Vulnerabilities: 2

CRITICAL  requests  2.19.0  GHSA-xxxx-yyyy-zzzz
HIGH      urllib3   1.24.1  GHSA-aaaa-bbbb-cccc

Report written to sentinel-report.json
```

*Illustrative output only; actual findings depend on the target dependency versions and current OSV data.*

## Architecture

```text
requirements.txt / pyproject.toml
             |
       Dependency parser
             |
       Pinned package set
             |
        OSV querybatch
             |
   Normalize + prioritize findings
             |
  JSON / SARIF / CycloneDX SBOM
```

## Security and accuracy boundaries

- The initial version checks **pinned direct declarations** only; it does not resolve complete transitive dependency trees.
- A clean result means no matching known OSV record was returned for the queried package/version. It does **not** prove that software is secure.
- The scanner sends package names and versions to OSV. Do not scan private dependency names if that disclosure is not permitted by your organization's policy.
- Network access is required for vulnerability lookups.
- Severity is taken from OSV metadata when available; missing severity is marked UNKNOWN, never assumed LOW.
- Review advisories and affected-version ranges before making remediation decisions.

## Run tests

```bash
python -m unittest discover -s tests -v
```

## Roadmap

- [ ] Resolve transitive dependencies and dependency graphs.
- [ ] Add npm `package-lock.json` and `pnpm-lock.yaml` support.
- [ ] Add license-policy checks and end-of-life package signals.
- [ ] Add GitHub Actions SARIF upload example.
- [ ] Add exploitability-aware prioritization and VEX status support.
- [ ] Benchmark precision/recall against a curated, versioned test corpus.

## Research and standards

- [OWASP Top 10:2025 — A03 Software Supply Chain Failures](https://owasp.org/Top10/A03_2025-Software_Supply_Chain_Failures/)
- [OSV API documentation](https://google.github.io/osv.dev/)
- [CycloneDX Specification](https://cyclonedx.org/specification/overview/)
- [CISA — Minimum Elements for a Software Bill of Materials](https://www.cisa.gov/resources-tools/resources/2025-minimum-elements-software-bill-materials-sbom)

## Career value

This project demonstrates practical skills in Python engineering, API integration, vulnerability intelligence, software inventory, security reporting, testing, and CI. For interviews, be ready to explain the limitations of version matching, why transitive dependencies matter, how you avoid false confidence, and how you would validate prioritization with a reproducible dataset.

## License

MIT — see [LICENSE](LICENSE).
