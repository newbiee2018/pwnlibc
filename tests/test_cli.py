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

    def test_remove_help(self, runner):
        result = runner.invoke(cli, ["remove", "--help"])
        assert result.exit_code == 0

    def test_source_help(self, runner):
        result = runner.invoke(cli, ["source", "--help"])
        assert result.exit_code == 0

    def test_source_download_help(self, runner):
        result = runner.invoke(cli, ["source", "download", "--help"])
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
            "--no-check-source",
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

    def test_auto_prefers_deb_with_debug(self, runner, minimal_elf_amd64, populated_glibc_dir):
        """Auto mode should pick deb(dbg) without prompting."""
        # 2.35/amd64 has .debug dir in the fixture
        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            mock_patch.return_value = minimal_elf_amd64.parent / (minimal_elf_amd64.name + ".patched")
            mock_patch.return_value.write_bytes(b"\x7fELF" + b"\x00" * 100)
            result = runner.invoke(cli, [
                "--glibc-dir", str(populated_glibc_dir),
                "patch", str(minimal_elf_amd64),
                "-v", "2.35",
            ])
        assert result.exit_code == 0
        assert "deb(dbg)" in result.output
        # Should NOT prompt
        assert "Choose" not in result.output

    def test_auto_falls_back_to_built_dbg(self, runner, minimal_elf_amd64, tmp_path):
        """Auto mode: deb without debug + built with debug → picks built."""
        glibc_dir = tmp_path / "glibc"
        # deb without debug
        deb_lib = glibc_dir / "2.31" / "amd64" / "lib"
        deb_lib.mkdir(parents=True)
        (deb_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (deb_lib / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (deb_lib / "libc.so.6").symlink_to("libc-2.31.so")
        (deb_lib / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")
        # built WITH debug
        built_lib = glibc_dir / "2.31" / "amd64-built" / "lib"
        built_lib.mkdir(parents=True)
        (built_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (built_lib / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (built_lib / "libc.so.6").symlink_to("libc-2.31.so")
        (built_lib / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")
        (built_lib / ".debug").mkdir()
        (built_lib / ".debug" / "libc-2.31.so.debug").write_bytes(b"\x00" * 10)

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            mock_patch.return_value = minimal_elf_amd64.parent / (minimal_elf_amd64.name + ".patched")
            mock_patch.return_value.write_bytes(b"\x7fELF" + b"\x00" * 100)
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(minimal_elf_amd64),
                "-v", "2.31",
            ])
        assert result.exit_code == 0
        assert "built" in result.output
        assert "Choose" not in result.output

    def test_auto_prompts_no_debug_choose_deb(self, runner, minimal_elf_amd64, populated_glibc_dir):
        """Auto mode: deb without debug, no built → prompt, user picks 2 (use deb)."""
        # 2.39/amd64 has no debug and no built variant
        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            mock_patch.return_value = minimal_elf_amd64.parent / (minimal_elf_amd64.name + ".patched")
            mock_patch.return_value.write_bytes(b"\x7fELF" + b"\x00" * 100)
            result = runner.invoke(cli, [
                "--glibc-dir", str(populated_glibc_dir),
                "patch", str(minimal_elf_amd64),
                "-v", "2.39",
            ], input="2\n")
        assert result.exit_code == 0
        assert "no debug symbols" in result.output.lower()
        assert "deb)" in result.output

    def test_auto_prompts_no_debug_choose_cancel(self, runner, minimal_elf_amd64, populated_glibc_dir):
        """Auto mode: deb without debug → prompt, user picks 3 (cancel)."""
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "patch", str(minimal_elf_amd64),
            "-v", "2.39",
        ], input="3\n")
        assert result.exit_code != 0
        assert "Cancel" in result.output or "Cancelled" in result.output


class TestCliRestore:
    def test_restore_no_backup(self, runner, tmp_path):
        binary = tmp_path / "nobak"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code != 0
        assert "No .patched file or backup found" in result.output


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
        assert "to download" in result.output or "already installed" in result.output


class TestCliSetup:
    def test_setup_detects_source_built(self, runner, tmp_path):
        """Archives with .a files should be classified as 'built' variant."""
        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        import tarfile
        arc_path = archive_dir / "2.31.tar.gz"
        with tarfile.open(arc_path, "w:gz") as tf:
            # Create source-built layout: version/arch/lib/ with .a files
            import io
            for name in [
                "2.31/amd64/lib/libc-2.31.so",
                "2.31/amd64/lib/ld-2.31.so",
                "2.31/amd64/lib/libc.a",          # <-- source-built marker
                "2.31/amd64/lib/libm.a",
                "2.31/amd64/libexec/getconf/test", # <-- source-built marker
                "2.31/source/malloc.c",
            ]:
                info = tarfile.TarInfo(name=name)
                info.size = 4
                tf.addfile(info, io.BytesIO(b"test"))

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "setup", str(archive_dir),
        ])
        assert result.exit_code == 0
        assert "built variant" in result.output
        assert (glibc_dir / "2.31" / "amd64-built" / "lib" / "libc-2.31.so").exists()
        assert (glibc_dir / "2.31" / "source" / "malloc.c").exists()
        assert not (glibc_dir / "2.31" / "amd64").exists()

    def test_setup_detects_deb_style(self, runner, tmp_path):
        """Archives without .a files should be classified as 'deb' variant."""
        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        import tarfile
        arc_path = archive_dir / "2.35.tar.gz"
        with tarfile.open(arc_path, "w:gz") as tf:
            import io
            for name in [
                "2.35/amd64/lib/libc.so.6",
                "2.35/amd64/lib/ld-linux-x86-64.so.2",
            ]:
                info = tarfile.TarInfo(name=name)
                info.size = 4
                tf.addfile(info, io.BytesIO(b"test"))

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "setup", str(archive_dir),
        ])
        assert result.exit_code == 0
        assert "deb variant" in result.output
        assert (glibc_dir / "2.35" / "amd64" / "lib" / "libc.so.6").exists()
        assert not (glibc_dir / "2.35" / "amd64-built").exists()

    def test_setup_force_variant(self, runner, tmp_path):
        """--variant built should force built variant regardless of content."""
        archive_dir = tmp_path / "archives"
        archive_dir.mkdir()
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        import tarfile
        arc_path = archive_dir / "2.35.tar.gz"
        with tarfile.open(arc_path, "w:gz") as tf:
            import io
            for name in [
                "2.35/amd64/lib/libc.so.6",
                "2.35/amd64/lib/ld-linux-x86-64.so.2",
            ]:
                info = tarfile.TarInfo(name=name)
                info.size = 4
                tf.addfile(info, io.BytesIO(b"test"))

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "setup", str(archive_dir), "--variant", "built",
        ])
        assert result.exit_code == 0
        assert (glibc_dir / "2.35" / "amd64-built" / "lib" / "libc.so.6").exists()


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
