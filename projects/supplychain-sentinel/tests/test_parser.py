import tempfile
import unittest
from pathlib import Path

from sentinel.parser import discover_dependencies, parse_requirements


class ParserTests(unittest.TestCase):
    def test_requirements_only_accepts_exact_pins(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "requirements.txt"
            path.write_text("requests==2.31.0\nflask>=2.0\n# comment\n", encoding="utf-8")
            dependencies, skipped = parse_requirements(path)
        self.assertEqual([(d.name, d.version) for d in dependencies], [("requests", "2.31.0")])
        self.assertEqual(len(skipped), 1)

    def test_project_directory_discovers_manifests(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "requirements.txt").write_text("urllib3==2.0.0\n", encoding="utf-8")
            dependencies, skipped = discover_dependencies(root)
        self.assertEqual(dependencies[0].name, "urllib3")
        self.assertEqual(skipped, [])


if __name__ == "__main__":
    unittest.main()
