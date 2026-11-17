import json
import unittest

from sentinel.report import build_findings, cyclonedx_report, sarif_report


class ReportTests(unittest.TestCase):
    def test_findings_are_prioritized_and_unknown_is_not_low(self):
        dependencies = [{"name": "demo", "version": "1.0", "source": "requirements.txt:1"}]
        osv = [[
            {"id": "OSV-HIGH", "database_specific": {"severity": "HIGH"}, "summary": "High issue"},
            {"id": "OSV-UNKNOWN", "summary": "Unscored issue"},
        ]]
        findings = build_findings(dependencies, osv)
        self.assertEqual(findings[0]["severity"], "HIGH")
        self.assertEqual(findings[1]["severity"], "UNKNOWN")

    def test_sarif_and_sbom_are_valid_json(self):
        self.assertEqual(json.loads(sarif_report([]))["version"], "2.1.0")
        self.assertEqual(json.loads(cyclonedx_report([]))["specVersion"], "1.5")


if __name__ == "__main__":
    unittest.main()
