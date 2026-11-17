"""Dependency manifest parsers. No third-party parser is required."""

from __future__ import annotations

import re
import tomllib
from dataclasses import asdict, dataclass
from pathlib import Path

PINNED = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*==\s*([A-Za-z0-9][A-Za-z0-9._+!-]*)")


@dataclass(frozen=True)
class Dependency:
    name: str
    version: str
    source: str

    def as_dict(self) -> dict[str, str]:
        return asdict(self)


def _normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_requirements(path: Path) -> tuple[list[Dependency], list[str]]:
    dependencies: list[Dependency] = []
    skipped: list[str] = []
    for line_no, raw in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith(("-r ", "--", "-e ")):
            if line and line.startswith(("-r ", "-e ")):
                skipped.append(f"{path.name}:{line_no}: include/editable directive not resolved")
            continue
        match = PINNED.match(line)
        if match:
            dependencies.append(Dependency(_normalize_name(match.group(1)), match.group(2), f"{path.name}:{line_no}"))
        else:
            skipped.append(f"{path.name}:{line_no}: not an exact == pin")
    return dependencies, skipped


def parse_pyproject(path: Path) -> tuple[list[Dependency], list[str]]:
    data = tomllib.loads(path.read_text(encoding="utf-8"))
    raw_dependencies = data.get("project", {}).get("dependencies", [])
    dependencies: list[Dependency] = []
    skipped: list[str] = []
    for index, declaration in enumerate(raw_dependencies, 1):
        match = PINNED.match(declaration)
        if match:
            dependencies.append(Dependency(_normalize_name(match.group(1)), match.group(2), f"{path.name}:project.dependencies[{index}]"))
        else:
            skipped.append(f"{path.name}:project.dependencies[{index}]: not an exact == pin")
    return dependencies, skipped


def discover_dependencies(target: Path) -> tuple[list[Dependency], list[str]]:
    if target.is_file():
        files = [target]
    elif target.is_dir():
        files = [p for p in (target / "requirements.txt", target / "pyproject.toml") if p.is_file()]
    else:
        raise FileNotFoundError(f"Target does not exist: {target}")

    if not files:
        raise FileNotFoundError("No requirements.txt or pyproject.toml found in target")

    all_deps: list[Dependency] = []
    skipped: list[str] = []
    for path in files:
        if path.name == "requirements.txt":
            deps, ignored = parse_requirements(path)
        elif path.name == "pyproject.toml":
            deps, ignored = parse_pyproject(path)
        else:
            raise ValueError(f"Unsupported manifest: {path.name}")
        all_deps.extend(deps)
        skipped.extend(ignored)

    # Keep separate source records, but avoid duplicate package/version queries.
    unique = {(d.name, d.version): d for d in all_deps}
    return sorted(unique.values(), key=lambda d: (d.name, d.version)), skipped
