from __future__ import annotations

import re
from pathlib import Path


def _read_pyproject_version(pyproject_path: Path) -> str:
    try:
        import tomllib  # py311+
    except ModuleNotFoundError:  # pragma: no cover
        raise SystemExit("python>=3.11 required (tomllib missing)")

    data = tomllib.loads(pyproject_path.read_text(encoding="utf-8"))
    version = (
        data.get("project", {}).get("version")
        if isinstance(data, dict)
        else None  # pragma: no cover - defensive
    )
    if not isinstance(version, str) or not version.strip():
        raise SystemExit("pyproject.toml missing [project].version")
    return version.strip()


def _require_pinned(spec: str, *, context: str) -> None:
    if "==" not in spec:
        raise SystemExit(f"unpinned dependency in {context}: {spec!r} (expected '==')")


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    pyproject = root / "pyproject.toml"
    changelog = root / "CHANGELOG.md"
    req_dev = root / "requirements-dev.txt"

    version = _read_pyproject_version(pyproject)

    # Changelog must have a versioned section for the current package version.
    changelog_text = changelog.read_text(encoding="utf-8")
    if not re.search(rf"^##\s+v{re.escape(version)}\b", changelog_text, flags=re.MULTILINE):
        raise SystemExit(f"CHANGELOG.md missing section header for v{version}")

    # `jwt-workbench --version` must match pyproject version (single-source-of-truth).
    from jwt_workbench.version import __version__  # imported late to keep script fast

    if __version__ != version:
        raise SystemExit(f"version mismatch: pyproject={version} package={__version__}")

    # Basic dependency pin drift guard: require `==` pins.
    try:
        import tomllib
    except ModuleNotFoundError:  # pragma: no cover
        tomllib = None  # type: ignore[assignment]
    data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
    deps = data.get("project", {}).get("dependencies", [])
    if deps and not isinstance(deps, list):
        raise SystemExit("pyproject.toml [project].dependencies must be a list")
    for dep in deps:
        if isinstance(dep, str) and dep.strip():
            _require_pinned(dep.strip(), context="pyproject.toml")

    for raw in req_dev.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(("-r", "--requirement")):
            continue
        _require_pinned(line, context="requirements-dev.txt")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
