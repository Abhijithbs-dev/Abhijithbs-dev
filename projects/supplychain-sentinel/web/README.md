# SupplyChain Sentinel Web App

A static dashboard plus a Python serverless API, deployable on Vercel.

## Local preview

From this directory, serve the static frontend:

```bash
python -m http.server 8080
```

Open http://localhost:8080. The scan endpoint requires the Vercel Python function runtime; for local end-to-end testing, install the Vercel CLI and run:

```bash
vercel dev
```

## Deploy

Import the GitHub repository into Vercel and set **Root Directory** to `projects/supplychain-sentinel/web`. Vercel detects `api/scan.py` as a Python function and serves `index.html` as the frontend. The included `vercel.json` gives the OSV lookup function up to 60 seconds.

## Data handling

The browser sends the manifest to this app's API. The API extracts exact-pinned package names and versions and sends only those coordinates to the public OSV API. Do not scan private package names if disclosure is not allowed by your policy. Request bodies are not intentionally logged by the endpoint.

## Scope

- Python `requirements.txt` and PEP 621 `pyproject.toml` direct dependencies.
- Exact `==` pins only; unsupported declarations are shown as skipped.
- Up to 100 unique pinned dependencies per request.
- Known vulnerabilities indexed by OSV. No transitive dependency resolution.
- Severity not provided by OSV metadata is labelled UNKNOWN, not LOW.
