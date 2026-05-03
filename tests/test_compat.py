"""Tests for Python version compatibility.

These tests verify whether pwnlibc can be imported on the current Python
version. On older Pythons (< 3.10) that lack PEP 604 union types and
PEP 585 lowercase generics, import will fail with SyntaxError.
"""

import sys

import pytest


class TestPythonVersionCompat:
    def test_python_version_reported(self):
        """Report the Python version for test logs."""
        print(f"Python version: {sys.version}")
        print(f"Python version tuple: {sys.version_info[:3]}")

    def test_import_pwnlibc(self):
        """Core import test — fails on Python < 3.10 due to type hint syntax."""
        import pwnlibc
        assert hasattr(pwnlibc, "__version__")

    def test_import_all_modules(self):
        """Verify all submodules import cleanly."""
        from pwnlibc import config
        from pwnlibc import elfutil
        from pwnlibc import backup
        from pwnlibc import glibc
        from pwnlibc import downloader
        from pwnlibc import patcher
        from pwnlibc import cli

    def test_type_hints_at_runtime(self):
        """Verify PEP 604 / PEP 585 type hints don't cause runtime errors."""
        from pwnlibc.config import parse_version
        result = parse_version("2.31")
        assert isinstance(result, tuple)
        assert result == (2, 31)

    def test_union_type_annotation(self):
        """Specifically test that `X | Y` syntax works at runtime."""
        from pwnlibc.downloader import DebPackage
        pkg = DebPackage(
            version="2.31",
            full_id="2.31-0ubuntu9_amd64",
            arch="amd64",
            filename="libc6_2.31-0ubuntu9_amd64.deb",
            dbg_filename=None,
        )
        assert pkg.dbg_filename is None
        pkg2 = DebPackage(
            version="2.31",
            full_id="2.31-0ubuntu9_amd64",
            arch="amd64",
            filename="libc6_2.31-0ubuntu9_amd64.deb",
            dbg_filename="libc6-dbg_2.31-0ubuntu9_amd64.deb",
        )
        assert pkg2.dbg_filename is not None

    def test_minimum_python_version(self):
        """Document the minimum required Python version."""
        if sys.version_info < (3, 10):
            pytest.skip(
                f"Python {'.'.join(map(str, sys.version_info[:3]))} is below "
                f"minimum required 3.10 (PEP 604 union types, PEP 585 generics)"
            )


class TestDependencies:
    def test_click_available(self):
        import click
        assert hasattr(click, "group")

    def test_rich_available(self):
        import rich
        from rich.console import Console
        from rich.table import Table
