"""Tests for pwnlibc.cli — Click CLI commands."""

import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import _pick_best, cli
from pwnlibc.downloader import DebPackage
from tests.conftest import (
    SAMPLE_MIRROR_HTML,
    SAMPLE_OLD_UBUNTU_MIRROR_HTML,
    build_test_binary,
)


@pytest.fixture
def runner():
    return CliRunner()


def _mk_pkg(full_id, mirror="ubuntu", arch="amd64"):
    """Construct a DebPackage from a full id like '2.31-0ubuntu9.16_amd64'."""
    version = full_id.rsplit("_", 1)[0].split("-")[0]
    return DebPackage(
        version=version,
        full_id=full_id,
        arch=arch,
        filename=f"libc6_{full_id}.deb",
        dbg_filename=None,
        mirror=mirror,
    )


def _old_releases_only(mock_fetch):
    """_fetch_index side effect: only old-releases has packages."""
    def fetch(url):
        if "old-releases" in url:
            return SAMPLE_OLD_UBUNTU_MIRROR_HTML
        return "<html></html>"
    mock_fetch.side_effect = fetch


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


class TestPickBest:
    """_pick_best must compare revisions dpkg-style, not lexicographically."""

    @pytest.mark.parametrize("older,newer", [
        ("2.23-0ubuntu3_amd64", "2.23-0ubuntu11.3_amd64"),
        ("2.6.1-1ubuntu9_amd64", "2.6.1-1ubuntu10_amd64"),
        ("2.31-0ubuntu9.16_amd64", "2.31-0ubuntu9.18_amd64"),
        ("2.35-0ubuntu3.1~esm1_amd64", "2.35-0ubuntu3.1_amd64"),
        ("2.19-10ubuntu2_amd64", "2.19-10ubuntu2.1_amd64"),
    ])
    def test_newest_revision_wins(self, older, newer):
        for ids in ([older, newer], [newer, older]):
            best = _pick_best([_mk_pkg(i) for i in ids])
            assert len(best) == 1
            assert list(best.values())[0].full_id == newer

    def test_tie_prefers_primary_mirror(self):
        """Same revision scraped from two mirrors: primary (ubuntu) wins."""
        for mirrors in (["old-ubuntu", "ubuntu"], ["ubuntu", "old-ubuntu"]):
            best = _pick_best([_mk_pkg("2.31-0ubuntu9.16_amd64", mirror=m) for m in mirrors])
            assert list(best.values())[0].mirror == "ubuntu"

    def test_tie_prefers_primary_mirror_non_x86(self):
        """arm64's primary mirror is ports, not ubuntu."""
        best = _pick_best([
            _mk_pkg("2.35-0ubuntu3.8_arm64", mirror="old-ubuntu", arch="arm64"),
            _mk_pkg("2.35-0ubuntu3.8_arm64", mirror="ports", arch="arm64"),
        ])
        assert list(best.values())[0].mirror == "ports"


class TestMirrorPropagation:
    """The mirror a package was scraped from must be the one downloaded from."""

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.downloader._fetch_index")
    def test_download_uses_scraped_mirror(self, mock_fetch, mock_dl, runner, tmp_path):
        """2.19 only exists on old-releases — must not 404 on archive.ubuntu.com."""
        _old_releases_only(mock_fetch)
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.19", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0].mirror == "old-ubuntu"
        assert mock_dl.call_args.kwargs["mirror"] == "old-ubuntu"

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_actual_mirror(self, mock_fetch, runner, tmp_path):
        """Mirror column shows where the package was found, not the arch default."""
        mock_fetch.return_value = SAMPLE_OLD_UBUNTU_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "available", "--arch", "amd64", "--mirror", "old-ubuntu",
            "--no-check-source",
        ])
        assert result.exit_code == 0
        # The table row (not just the "fetching" line) names old-ubuntu
        assert re.search(r"2\.19.*amd64.*old-ubuntu", result.output)

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_verify_uses_scraped_mirror(self, mock_fetch, mock_verify, runner, tmp_path):
        _old_releases_only(mock_fetch)
        glibc_dir = tmp_path / "glibc"
        lib = glibc_dir / "2.19" / "amd64" / "lib"
        lib.mkdir(parents=True)
        (lib / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (lib / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF" + b"\x00" * 100)

        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "verify"])
        assert result.exit_code == 0
        mock_verify.assert_called_once()
        assert mock_verify.call_args.kwargs["mirror"] == "old-ubuntu"


class TestRemoveSourceRule:
    """--variant all + specific --arch: source follows auto-removal only."""

    @staticmethod
    def _make_install(glibc_dir, version, arch):
        lib = glibc_dir / version / arch / "lib"
        lib.mkdir(parents=True, exist_ok=True)
        (lib / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (lib / "ld-linux-x86-64.so.2").write_bytes(b"\x7fELF" + b"\x00" * 100)

    def test_remove_arch_keeps_shared_source(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._make_install(glibc_dir, "2.31", "amd64")
        self._make_install(glibc_dir, "2.31", "i686")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "amd64").exists()
        assert (glibc_dir / "2.31" / "i686").is_dir()
        assert (glibc_dir / "2.31" / "source").is_dir()

        # Removing the last arch takes the (now orphaned) source with it
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--arch", "i686",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "source").exists()
        assert not (glibc_dir / "2.31").exists()

    def test_remove_all_arches_removes_source(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._make_install(glibc_dir, "2.31", "amd64")
        self._make_install(glibc_dir, "2.31", "i686")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "remove", "2.31"])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31").exists()

    def test_remove_variant_source_only(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        self._make_install(glibc_dir, "2.31", "amd64")
        (glibc_dir / "2.31" / "source").mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "source",
        ])
        assert result.exit_code == 0
        assert not (glibc_dir / "2.31" / "source").exists()
        assert (glibc_dir / "2.31" / "amd64").is_dir()


class TestVerifyExitCode:
    """verify must exit non-zero when problems remain (or a fix fails)."""

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_exit_zero_all_match(self, mock_fetch, mock_verify, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "verify"])
        assert result.exit_code == 0
        assert "verified OK" in result.output
        # Same index mocked for every mirror: tie-break keeps the primary
        assert mock_verify.call_args.kwargs["mirror"] == "ubuntu"

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_exit_nonzero_on_mismatch(self, mock_fetch, mock_verify, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MISMATCH", "expected=aa got=bb")]
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "verify"])
        assert result.exit_code == 1

    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_exit_nonzero_on_missing(self, mock_fetch, mock_verify, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MISSING", "")]
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "verify"])
        assert result.exit_code == 1

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_fix_success_exits_zero(self, mock_fetch, mock_verify, mock_dl,
                                    runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MISSING", "")]
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "verify", "--fix"])
        assert result.exit_code == 0
        assert mock_dl.called

    @patch("pwnlibc.cli.download_glibc", side_effect=RuntimeError("boom"))
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_fix_failure_exits_nonzero(self, mock_fetch, mock_verify, mock_dl,
                                       runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MISSING", "")]
        result = runner.invoke(cli, ["--glibc-dir", str(populated_glibc_dir), "verify", "--fix"])
        assert result.exit_code == 1


class TestDownloadSourcePassthrough:
    """The source URL is resolved once by the caller and passed through."""

    URL = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"

    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available")
    def test_source_download_passes_url(self, mock_check, mock_dl_source, runner, tmp_path):
        mock_check.return_value = self.URL
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "source", "download", "2.31",
        ])
        assert result.exit_code == 0
        mock_check.assert_called_once_with("2.31")
        mock_dl_source.assert_called_once()
        assert mock_dl_source.call_args.kwargs["url"] == self.URL

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.downloader._fetch_index")
    def test_download_command_source_step_single_check(
            self, mock_fetch, mock_check, mock_dl_source, mock_dl_glibc, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_check.return_value = self.URL
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg", "--source",
        ])
        assert result.exit_code == 0
        mock_check.assert_called_once_with("2.31")  # no second HEAD round-trip
        mock_dl_source.assert_called_once()
        assert mock_dl_source.call_args.kwargs["url"] == self.URL

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available", return_value=None)
    @patch("pwnlibc.downloader._fetch_index")
    def test_download_command_source_unavailable(
            self, mock_fetch, mock_check, mock_dl_source, mock_dl_glibc, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg", "--source",
        ])
        assert result.exit_code == 0
        mock_dl_source.assert_not_called()
        assert "not available on ftp.gnu.org" in result.output


# ---------------------------------------------------------------------------
# Ownership repair after privileged writes / graceful remove
# ---------------------------------------------------------------------------

@patch("pwnlibc.cli.chown_tree")
@patch("pwnlibc.cli.download_glibc")
@patch("pwnlibc.cli._scrape_mirrors")
def test_download_chowns_after_write(mock_scrape, mock_dl, mock_chown, tmp_path):
    # scrape returns one 2.31/amd64 pkg (reuse the fixtures the existing
    # download tests use); download_glibc is a MagicMock
    mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
    mock_chown.return_value = 0  # defined int; _chown_after_write compares > 0
    result = CliRunner().invoke(cli, [
        "--glibc-dir", str(tmp_path),
        "download", "2.31", "--no-source",
    ])
    assert result.exit_code == 0
    mock_chown.assert_called_once_with(tmp_path)

@patch("pwnlibc.cli.shutil.rmtree", side_effect=PermissionError("denied"))
def test_remove_permission_error_prints_hint(mock_rmtree, populated_glibc_dir):
    # populated_glibc_dir has no 2.27 — remove a version it actually has,
    # so the rmtree PermissionError path is reached.
    result = CliRunner().invoke(cli, [
        "--glibc-dir", str(populated_glibc_dir),
        "remove", "2.31",
    ])
    assert result.exit_code == 1
    assert "chown" in result.output


# ---------------------------------------------------------------------------
# Opt-in --verify-signatures wiring
# ---------------------------------------------------------------------------

class TestDownloadVerifySignatures:
    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_fail_exits_1(self, mock_scrape, mock_dl, mock_chown, mock_sig,
                          tmp_path):
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0  # real exit path, not a TypeError in _chown
        mock_sig.return_value = False
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 1
        # reached via sys.exit(1), not an unhandled exception
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_sig.assert_called_once()
        # the actually-downloaded pkg, this run's glibc dir, no explicit keyring
        pkgs, glibc_dir, keyring = mock_sig.call_args[0]
        assert [p.full_id for p in pkgs] == ["2.31-0ubuntu9.16_amd64"]
        assert glibc_dir == tmp_path
        assert keyring is None

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_clean_exits_0(self, mock_scrape, mock_dl, mock_chown, mock_sig,
                           tmp_path):
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0
        mock_sig.return_value = True
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 0
        mock_sig.assert_called_once()

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_off_by_default(self, mock_scrape, mock_dl, mock_chown, mock_sig,
                            tmp_path):
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source",
        ])
        assert result.exit_code == 0
        mock_sig.assert_not_called()

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_keyring_passed_through(self, mock_scrape, mock_dl, mock_chown,
                                    mock_sig, tmp_path):
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0
        mock_sig.return_value = True
        kr = tmp_path / "kr.gpg"
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
            "--keyring", str(kr),
        ])
        assert result.exit_code == 0
        assert mock_sig.call_args[0][2] == kr

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_runs_before_chown(self, mock_scrape, mock_dl, mock_chown,
                               mock_sig, tmp_path):
        """Binding placement ruling: content is verified, ownership repaired last."""
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0
        calls = []
        mock_sig.side_effect = lambda *a: calls.append("sig") or True
        mock_chown.side_effect = lambda d: calls.append("chown") or 0
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 0
        assert calls == ["sig", "chown"]


class TestDownloadAllVerifySignatures:
    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_fail_exits_1(self, mock_scrape, mock_dl, mock_chown, mock_sig,
                          tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0  # real exit path, not a TypeError in _chown
        mock_sig.return_value = False
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--verify-signatures",
        ])
        assert result.exit_code == 1
        # reached via sys.exit(1), not an unhandled exception
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_sig.assert_called_once()

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_clean_exits_0(self, mock_scrape, mock_dl, mock_chown, mock_sig,
                           tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_chown.return_value = 0
        mock_sig.return_value = True
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--verify-signatures",
        ])
        assert result.exit_code == 0

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_runs_before_chown(self, mock_scrape, mock_dl, mock_chown,
                               mock_sig, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        calls = []
        mock_sig.side_effect = lambda *a: calls.append("sig") or True
        mock_chown.side_effect = lambda d: calls.append("chown") or 0
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--verify-signatures",
        ])
        assert result.exit_code == 0
        assert calls == ["sig", "chown"]


class TestVerifyCommandSignatures:
    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_sig_failure_exits_1_even_when_files_match(
            self, mock_fetch, mock_verify, mock_sig, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        mock_sig.return_value = False
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "verify", "--verify-signatures",
        ])
        assert result.exit_code == 1
        # reached via sys.exit(1), not an unhandled exception
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_sig.assert_called_once()

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_clean_exits_0(
            self, mock_fetch, mock_verify, mock_sig, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        mock_sig.return_value = True
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "verify", "--verify-signatures",
        ])
        assert result.exit_code == 0

    @patch("pwnlibc.cli._run_signature_checks")
    @patch("pwnlibc.cli.verify_against_deb")
    @patch("pwnlibc.downloader._fetch_index")
    def test_off_by_default(
            self, mock_fetch, mock_verify, mock_sig, runner, populated_glibc_dir):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        mock_verify.return_value = [("libc.so.6", "MATCH", "deadbeefdeadbeef")]
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "verify",
        ])
        assert result.exit_code == 0
        mock_sig.assert_not_called()
