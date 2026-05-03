"""Tests for pwnlibc.cli — Click CLI commands."""

import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import cli
from tests.conftest import build_test_binary


@pytest.fixture
def runner():
    return CliRunner()


class TestCliHelp:
    def test_main_help(self, runner):
        result = runner.invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "pwnlibc" in result.output
        assert "list" in result.output
        assert "patch" in result.output
        assert "download" in result.output

    def test_list_help(self, runner):
        result = runner.invoke(cli, ["list", "--help"])
        assert result.exit_code == 0
        assert "--arch" in result.output

    def test_patch_help(self, runner):
        result = runner.invoke(cli, ["patch", "--help"])
        assert result.exit_code == 0
        assert "--version" in result.output
        assert "--mode" in result.output

    def test_download_help(self, runner):
        result = runner.invoke(cli, ["download", "--help"])
        assert result.exit_code == 0
        assert "--mirror" in result.output

    def test_download_all_help(self, runner):
        result = runner.invoke(cli, ["download-all", "--help"])
        assert result.exit_code == 0
        assert "--check" in result.output

    def test_verify_help(self, runner):
        result = runner.invoke(cli, ["verify", "--help"])
        assert result.exit_code == 0
        assert "--fix" in result.output

    def test_info_help(self, runner):
        result = runner.invoke(cli, ["info", "--help"])
        assert result.exit_code == 0

    def test_restore_help(self, runner):
        result = runner.invoke(cli, ["restore", "--help"])
        assert result.exit_code == 0

    def test_setup_help(self, runner):
        result = runner.invoke(cli, ["setup", "--help"])
        assert result.exit_code == 0


class TestCliList:
    def test_list_empty(self, runner, tmp_path):
        glibc_dir = tmp_path / "empty_glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "No glibc versions found" in result.output

    def test_list_populated(self, runner, populated_glibc_dir):
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "list"])
        assert result.exit_code == 0
        assert "2.31" in result.output
        assert "2.35" in result.output

    def test_list_filter_arch(self, runner, populated_glibc_dir):
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir), "list", "--arch", "i686",
        ])
        assert result.exit_code == 0
        assert "2.31" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_command(self, mock_fetch, runner, populated_glibc_dir):
        from tests.conftest import SAMPLE_MIRROR_HTML
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir), "available", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert "Available" in result.output


class TestCliInfo:
    def test_info_synthetic_elf(self, runner, minimal_elf_amd64):
        result = runner.invoke(cli, ["info", str(minimal_elf_amd64)])
        assert result.exit_code == 0
        assert "amd64" in result.output
        assert "NEEDED" in result.output

    def test_info_nonexistent(self, runner, tmp_path):
        result = runner.invoke(cli, ["info", str(tmp_path / "nonexistent")])
        assert result.exit_code != 0


class TestCliPatch:
    def test_patch_missing_version(self, runner, minimal_elf_amd64, populated_glibc_dir):
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "patch", str(minimal_elf_amd64),
            "-v", "2.99",
        ])
        assert result.exit_code != 0

    def test_patch_missing_binary(self, runner, populated_glibc_dir):
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "patch", "/nonexistent/binary",
            "-v", "2.31",
        ])
        assert result.exit_code != 0


class TestCliRestore:
    def test_restore_no_backup(self, runner, tmp_path):
        binary = tmp_path / "nobak"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code != 0
        assert "No backup found" in result.output


class TestCliDownload:
    @patch("pwnlibc.downloader._fetch_index")
    def test_download_version_not_found(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = "<html></html>"
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.99",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output


class TestCliDownloadAll:
    @patch("pwnlibc.downloader._fetch_index")
    def test_download_all_check_dry_run(self, mock_fetch, runner, populated_glibc_dir):
        from tests.conftest import SAMPLE_MIRROR_HTML
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "download-all", "--check",
        ])
        assert result.exit_code == 0
        assert "entries to download" in result.output or "already installed" in result.output


class TestCliModuleEntry:
    def test_python_m_pwnlibc(self):
        """Verify `python -m pwnlibc --help` works."""
        import os
        result = subprocess.run(
            [sys.executable, "-m", "pwnlibc", "--help"],
            capture_output=True, text=True,
            cwd=str(Path(__file__).parent.parent),
            env={**os.environ, "PYTHONPATH": str(Path(__file__).parent.parent)},
        )
        assert result.returncode == 0
        assert "pwnlibc" in result.stdout
