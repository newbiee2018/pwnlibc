"""Packaging metadata sanity: entry point, version single-sourcing, deps.

Guards the pipx/pip install path — a typo in [project.scripts] would only
surface at install time otherwise.
"""

from pathlib import Path
import re

import pytest

ROOT = Path(__file__).resolve().parent.parent
PYPROJECT = ROOT / "pyproject.toml"

try:
    import tomllib

    def _load():
        return tomllib.loads(PYPROJECT.read_text())
except ImportError:  # Python < 3.11
    import re

    def _load():
        text = PYPROJECT.read_text()
        return {"_text": text}


def _requires_tomllib():
    if "tomllib" not in globals():
        pytest.skip("tomllib requires Python 3.11+")


def test_pyproject_exists_and_declares_package():
    _requires_tomllib()
    data = _load()
    assert data["project"]["name"] == "pwnlibc"
    assert data["project"]["dependencies"] == ["click>=8.0", "rich>=13.0"]
    assert data["tool"]["setuptools"]["packages"] == ["pwnlibc"]


def test_console_script_points_at_click_group():
    _requires_tomllib()
    data = _load()
    assert data["project"]["scripts"] == {"pwnlibc": "pwnlibc.cli:cli"}

    from pwnlibc.cli import cli

    assert callable(cli)


def test_version_single_sourced():
    _requires_tomllib()
    data = _load()
    assert data["project"]["dynamic"] == ["version"]
    assert data["tool"]["setuptools"]["dynamic"]["version"]["attr"] == "pwnlibc.__version__"

    import pwnlibc

    assert pwnlibc.__version__


def test_dependencies_cover_requirements_txt():
    _requires_tomllib()
    reqs = [
        line.strip()
        for line in (ROOT / "requirements.txt").read_text().splitlines()
        if line.strip()
    ]
    deps = " ".join(_load()["project"]["dependencies"])
    for req in reqs:
        name = re.split(r"[><=!~\[]", req, maxsplit=1)[0]
        assert name in deps, f"requirements.txt entry {req!r} missing from pyproject dependencies"
