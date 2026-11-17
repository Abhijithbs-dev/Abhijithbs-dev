import unittest
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "web"))

from api.scan import build_response, get_severity, parse_manifest


class WebApiTests(unittest.TestCase):
    def test_requirements_manifest_normalizes_and_skips_unpinned(self):
        deps, skipped = parse_manifest("Requests==2.31.0\nflask>=2.0\nrequests==2.31.0\n", "requirements")
        self.assertEqual([(d["name"], d["version"]) for d in deps], [("requests", "2.31.0")])
        self.assertEqual(len(skipped), 1)

    def test_pyproject_manifest(self):
        raw = '[project]\ndependencies = ["urllib3==2.0.0", "httpx>=0.20"]\n'
        deps, skipped = parse_manifest(raw, "pyproject")
        self.assertEqual(deps[0]["name"], "urllib3")
        self.assertEqual(len(skipped), 1)

    def test_missing_severity_is_unknown(self):
        self.assertEqual(get_severity({"summary": "No score"}), "UNKNOWN")

    def test_build_response_prioritizes_findings(self):
        deps = [{"name": "demo", "version": "1.0", "source": "requirements.txt:1"}]
        osv = [{"vulns": [
            {"id": "OSV-LOW", "database_specific": {"severity": "LOW"}, "summary": "Low"},
            {"id": "OSV-HIGH", "database_specific": {"severity": "HIGH"}, "summary": "High"}
        ]}]
        report = build_response(deps, [], osv)
        self.assertEqual(report["findings"][0]["id"], "OSV-HIGH")
        self.assertEqual(report["summary"]["severity_counts"]["HIGH"], 1)


if __name__ == "__main__":
    unittest.main()
