"""Tests for pwnlibc.cli — Click CLI commands."""

import re
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import _pick_best, _resolve_latest, cli
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


def test_version_flag():
    result = CliRunner().invoke(cli, ["--version"])
    assert result.exit_code == 0
    assert "0.1.0" in result.output


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


# ---------------------------------------------------------------------------
# download latest — newest glibc per arch from the mirror chain
# ---------------------------------------------------------------------------

def _latest_chain_pkgs():
    """Post-chain-filter fixture: newest glibc is 2.39 on both x86 arches."""
    return [
        _mk_pkg("2.27-3ubuntu1.4_amd64"),
        _mk_pkg("2.31-0ubuntu9.16_amd64"),
        _mk_pkg("2.39-0ubuntu8.3_amd64"),
        _mk_pkg("2.27-3ubuntu1.4_i686", arch="i686"),
        _mk_pkg("2.39-0ubuntu8.3_i686", arch="i686"),
    ]


class TestResolveLatest:
    def test_resolve_latest_picks_max_per_arch(self):
        pkgs = _latest_chain_pkgs()
        assert _resolve_latest(pkgs, ["amd64", "i686"]) == {
            "amd64": "2.39",
            "i686": "2.39",
        }

    def test_resolve_latest_omits_empty_arch(self):
        pkgs = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        assert _resolve_latest(pkgs, ["amd64", "arm64"]) == {"amd64": "2.31"}

    def test_resolve_latest_orders_numerically(self):
        """2.10 > 2.9 — not lexicographic."""
        pkgs = [_mk_pkg("2.9-1ubuntu10_amd64"), _mk_pkg("2.10-1ubuntu1_amd64")]
        assert _resolve_latest(pkgs, ["amd64"]) == {"amd64": "2.10"}


class TestDownloadLatest:
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_resolves_newest(self, mock_scrape, mock_dl, tmp_path):
        mock_scrape.return_value = _latest_chain_pkgs()
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        assert "latest (amd64)" in result.output and "2.39" in result.output
        assert mock_dl.call_args[0][0].version == "2.39"

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_mixed_with_explicit(self, mock_scrape, mock_dl, tmp_path):
        mock_scrape.return_value = _latest_chain_pkgs()
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "latest", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        assert mock_dl.call_count == 2
        downloaded = {call.args[0].version for call in mock_dl.call_args_list}
        assert downloaded == {"2.31", "2.39"}

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_dedupes_explicit(self, mock_scrape, mock_dl, tmp_path):
        """latest resolving to an explicitly given version downloads it once."""
        mock_scrape.return_value = _latest_chain_pkgs()
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.39", "latest", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        assert "latest (amd64)" in result.output
        assert mock_dl.call_count == 1

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_unresolvable_arch(self, mock_scrape, mock_dl, tmp_path):
        """Chain has no packages for the arch: red per-arch error, exit 1,
        no traceback, and no literal-version 'not found' message for the token."""
        mock_scrape.return_value = []
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 1
        assert "latest (amd64): no packages found on mirrors" in result.output
        assert "ubuntu" in result.output  # the tried mirror list is named
        assert ": not found on mirrors" not in result.output
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_dl.assert_not_called()

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_partial_arch(self, mock_scrape, mock_dl, tmp_path):
        """--arch all with i686 missing: amd64 still resolves and downloads,
        i686 gets the red per-arch error."""
        mock_scrape.return_value = [_mk_pkg("2.39-0ubuntu8.3_amd64")]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--no-source",
        ])
        assert result.exit_code == 0
        assert "latest (amd64)" in result.output
        assert "latest (i686): no packages found on mirrors" in result.output
        mock_dl.assert_called_once()

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_legacy_chain(self, mock_scrape, mock_dl, tmp_path):
        """powerpc's chain is old-releases only; latest resolves the old
        newest just the same."""
        mock_scrape.return_value = [
            _mk_pkg("2.19-0ubuntu9_powerpc", mirror="old-ubuntu", arch="powerpc"),
            _mk_pkg("2.23-0ubuntu11_powerpc", mirror="old-ubuntu", arch="powerpc"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--arch", "powerpc", "--no-source",
        ])
        assert result.exit_code == 0
        assert "latest (powerpc)" in result.output
        assert "2.23" in result.output
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0].version == "2.23"

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_explicit_mirror(self, mock_scrape, mock_dl, tmp_path):
        """Exact-mirror mode: latest resolves within the raw scrape of
        --mirror (no auto chain filtering)."""
        mock_scrape.return_value = [
            _mk_pkg("2.28-10_amd64", mirror="debian"),
            _mk_pkg("2.36-9+deb12u3_amd64", mirror="debian"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--arch", "amd64", "--mirror", "debian",
            "--no-source",
        ])
        assert result.exit_code == 0
        assert "latest (amd64)" in result.output and "2.36" in result.output
        mock_dl.assert_called_once()
        assert mock_dl.call_args[0][0].version == "2.36"
        assert mock_dl.call_args.kwargs["mirror"] == "debian"


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


class TestDownloadAllSource:
    """Opt-in --source on download-all (download keeps its default-on)."""

    URL = "https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz"

    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_all_source_downloads_once_per_new_version(
            self, mock_scrape, mock_dl, mock_check, mock_src, mock_chown,
            tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [
            _mk_pkg("2.31-0ubuntu9.16_amd64"),
            _mk_pkg("2.35-0ubuntu3.1_amd64"),
        ]
        mock_chown.return_value = 0
        mock_check.return_value = self.URL

        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--source",
        ])
        assert result.exit_code == 0
        assert mock_dl.call_count == 2  # one deb per new version
        assert mock_src.call_count == 2  # one source per new version
        assert [c.args[0] for c in mock_src.call_args_list] == ["2.31", "2.35"]
        assert all(c.kwargs.get("url") == self.URL
                   for c in mock_src.call_args_list)

    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_all_source_off_by_default(
            self, mock_scrape, mock_dl, mock_check, mock_src, mock_chown,
            tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [
            _mk_pkg("2.31-0ubuntu9.16_amd64"),
            _mk_pkg("2.35-0ubuntu3.1_amd64"),
        ]
        mock_chown.return_value = 0

        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all",
        ])
        assert result.exit_code == 0
        assert mock_dl.call_count == 2
        mock_src.assert_not_called()
        mock_check.assert_not_called()

    @patch("pwnlibc.cli.chown_tree")
    @patch("pwnlibc.cli.download_source")
    @patch("pwnlibc.builder.check_source_available")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_all_source_runs_before_chown(
            self, mock_scrape, mock_dl, mock_check, mock_src, mock_chown,
            tmp_path):
        """Source downloads are writes: they must precede the ownership repair."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_check.return_value = self.URL
        calls = []
        mock_src.side_effect = lambda *a, **k: calls.append("source")
        mock_chown.side_effect = lambda d: calls.append("chown") or 0

        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--source",
        ])
        assert result.exit_code == 0
        assert calls == ["source", "chown"]


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


class TestBuildOfflineLocalSource:
    """The CLI must not gate on a remote HEAD when a local source tree works.

    build_glibc reuses <glibc_dir>/<version>/source (Task 5), but the CLI
    pre-check hit ftp.gnu.org first — a fully offline machine with local
    source was blocked at the CLI layer.
    """

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.builder.build_glibc")
    @patch("pwnlibc.builder.check_source_available", return_value=None)
    @patch("pwnlibc.builder.check_build_deps", return_value=[])
    def test_build_uses_local_source_without_remote_check(
            self, mock_deps, mock_check, mock_build, mock_chown, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        local_src = glibc_dir / "2.31" / "source" / "glibc-2.31"
        local_src.mkdir(parents=True)
        (local_src / "configure").write_text("#!/bin/sh\nexit 0\n")
        out_dir = glibc_dir / "2.31" / "amd64-built"

        def fake_build(version, arch, gdir, **kw):
            out_dir.mkdir(parents=True, exist_ok=True)
            return out_dir

        mock_build.side_effect = fake_build

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "build", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        mock_check.assert_not_called()  # no remote HEAD needed
        mock_build.assert_called_once()
        assert "using local source" in result.output

    @patch("pwnlibc.cli.patch_inplace")
    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.builder.build_glibc")
    @patch("pwnlibc.builder.check_source_available", return_value=None)
    @patch("pwnlibc.builder.check_build_deps", return_value=[])
    def test_patch_prompt_build_uses_local_source_offline(
            self, mock_deps, mock_check, mock_build, mock_chown, mock_patch,
            runner, tmp_path):
        """patch's build-from-source prompt hits the same remote gate."""
        from tests.conftest import _build_minimal_elf
        glibc_dir = tmp_path / "glibc"
        lib_dir = glibc_dir / "2.31" / "amd64" / "lib"  # deb without debug
        lib_dir.mkdir(parents=True)
        (lib_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
        (lib_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
        (lib_dir / "libc.so.6").symlink_to("libc-2.31.so")
        (lib_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")
        local_src = glibc_dir / "2.31" / "source" / "glibc-2.31"
        local_src.mkdir(parents=True)
        (local_src / "configure").write_text("#!/bin/sh\nexit 0\n")

        built_lib = glibc_dir / "2.31" / "amd64-built" / "lib"

        def fake_build(version, arch, gdir, **kw):
            built_lib.mkdir(parents=True, exist_ok=True)
            (built_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
            (built_lib / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 16)
            (built_lib / "libc.so.6").symlink_to("libc-2.31.so")
            (built_lib / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")
            return glibc_dir / "2.31" / "amd64-built"

        mock_build.side_effect = fake_build
        binary = _build_minimal_elf(tmp_path / "vuln", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "patch", str(binary), "-v", "2.31",
        ], input="1\n")  # prompt: build from source
        assert result.exit_code == 0
        mock_build.assert_called_once()
        mock_check.assert_not_called()
        assert "Build complete" in result.output


class TestDownloadAllExitSemantics:
    """download-all must exit 1 when nothing succeeded, like download does —
    provisioning scripts key off the exit code."""

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.download_glibc", side_effect=RuntimeError("net down"))
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_all_downloads_failed_exits_1(self, mock_scrape, mock_dl, mock_chown,
                                          tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]

        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all",
        ])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_chown.assert_not_called()  # nothing written -> no ownership pass

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_partial_failure_still_exits_0(self, mock_scrape, mock_dl, mock_chown,
                                           tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_scrape.return_value = [
            _mk_pkg("2.31-0ubuntu9.16_amd64"),
            _mk_pkg("2.35-0ubuntu3.1_amd64"),
        ]
        mock_dl.side_effect = [None, RuntimeError("net down")]  # 2.31 ok

        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all",
        ])
        assert result.exit_code == 0


class TestMaybeDownloadSourceNeverRaises:
    """_maybe_download_source promises "warn (never raise) on unavailability
    or failure" — an error from the availability check itself must not crash
    the command or mislabel the deb install as failed."""

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.builder.check_source_available",
           side_effect=OSError("network unreachable"))
    @patch("pwnlibc.downloader._fetch_index")
    def test_source_check_error_never_crashes_download(
            self, mock_fetch, mock_check, mock_dl, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg",
        ])
        assert result.exit_code == 0
        assert result.exception is None
        mock_dl.assert_called_once()
        assert "network unreachable" in result.output  # surfaced as a warning


class TestSignatureFailHintWording:
    """A signature-only FAIL never re-fetched any index — the tampering hint
    must not claim it did."""

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.verify_index_signature")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_signature_only_fail_gets_signature_hint(
            self, mock_scrape, mock_dl, mock_vis, mock_chown, tmp_path):
        from pwnlibc.signatures import IndexCheck

        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_vis.return_value = IndexCheck(
            suite="focal", index_file=None, index_sha_ok=None,
            signature_ok=False, notes=[])
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 1
        assert "FAIL" in result.output
        assert "signature was rejected" in result.output
        assert "re-fetched" not in result.output

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.verify_index_signature")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_index_mismatch_fail_keeps_refetch_hint(
            self, mock_scrape, mock_dl, mock_vis, mock_chown, tmp_path):
        from pwnlibc.signatures import IndexCheck

        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_vis.return_value = IndexCheck(
            suite="focal", index_file=None, index_sha_ok=False,
            signature_ok=True, notes=[])
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 1
        assert "re-fetched and still disagrees" in result.output

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.verify_index_signature")
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_verified_with_note_prints_ok_not_skipped(
            self, mock_scrape, mock_dl, mock_vis, mock_chown, tmp_path):
        """A check that actually verified (both verdicts True) but refreshed
        a stale cached index is an ok, not a skip."""
        from pwnlibc.signatures import IndexCheck

        mock_scrape.return_value = [_mk_pkg("2.31-0ubuntu9.16_amd64")]
        mock_vis.return_value = IndexCheck(
            suite="focal", index_file=None, index_sha_ok=True,
            signature_ok=True, notes=["cached index was stale; refreshed"])
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.31", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 0
        assert "skipped" not in result.output
        assert "ok" in result.output
        assert "cached index was stale; refreshed" in result.output


class TestBuildAndSourceDownloadExitSemantics:
    """build and source download exit 1 when every version failed — the same
    contract download/download-all already enforce (9bd2489)."""

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.builder.build_glibc")
    @patch("pwnlibc.builder.check_source_available", return_value=None)
    @patch("pwnlibc.builder.check_build_deps", return_value=[])
    def test_build_all_versions_skipped_exits_1(
            self, mock_deps, mock_check, mock_build, mock_chown,
            runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()  # no local source, nothing remote -> all skipped
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "build", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        mock_build.assert_not_called()
        assert "source not found" in result.output

    @patch("pwnlibc.builder.check_source_available", return_value=None)
    def test_source_download_all_unavailable_exits_1(
            self, mock_check, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "source", "download", "2.31",
        ])
        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "not available" in result.output

    @patch("pwnlibc.builder.check_source_available")
    def test_source_download_already_present_exits_0(
            self, mock_check, runner, tmp_path):
        """Idempotent no-op (source already there) stays a success."""
        src = tmp_path / "glibc" / "2.31" / "source" / "glibc-2.31"
        src.mkdir(parents=True)
        (src / "configure").write_text("#!/bin/sh\n")
        result = runner.invoke(cli, [
            "--glibc-dir", str(tmp_path / "glibc"),
            "source", "download", "2.31",
        ])
        assert result.exit_code == 0
        mock_check.assert_not_called()



class TestDownloadLatestArchScoping:
    """latest-derived versions stay scoped to the arch they resolved for."""

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_diverging_arches_scoped(self, mock_scrape, mock_dl, tmp_path):
        """amd64 latest 2.43 / i686 latest 2.39: exactly the two requested
        (version, arch) pairs download — the i686 version must not leak onto
        amd64 (and vice versa)."""
        mock_scrape.return_value = [
            _mk_pkg("2.39-0ubuntu8.3_amd64"),
            _mk_pkg("2.43-1ubuntu1_amd64"),
            _mk_pkg("2.39-0ubuntu8.3_i386", arch="i686"),
            _mk_pkg("2.35-0ubuntu3_i386", arch="i686"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--no-source",
        ])
        assert result.exit_code == 0
        downloaded = {(c.args[0].version, c.args[0].arch)
                      for c in mock_dl.call_args_list}
        assert downloaded == {("2.43", "amd64"), ("2.39", "i686")}

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_equal_versions_dedupe_per_arch(self, mock_scrape, mock_dl, tmp_path):
        """Both arches resolving to the same version downloads it once per
        arch — deduped as a version, not as a pair."""
        mock_scrape.return_value = [
            _mk_pkg("2.39-0ubuntu8.3_amd64"),
            _mk_pkg("2.35-0ubuntu3_amd64"),
            _mk_pkg("2.39-0ubuntu8.3_i386", arch="i686"),
            _mk_pkg("2.35-0ubuntu3_i386", arch="i686"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "--no-source",
        ])
        assert result.exit_code == 0
        downloaded = {(c.args[0].version, c.args[0].arch)
                      for c in mock_dl.call_args_list}
        assert downloaded == {("2.39", "amd64"), ("2.39", "i686")}

    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_download_latest_explicit_token_widens_scope(self, mock_scrape, mock_dl, tmp_path):
        """`latest 2.43` with latest(amd64)->2.43: the explicit token still
        covers every requested arch (i686/2.43 is not dropped)."""
        mock_scrape.return_value = [
            _mk_pkg("2.43-1ubuntu1_amd64"),
            _mk_pkg("2.43-1ubuntu1_i386", arch="i686"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "latest", "2.43", "--no-source",
        ])
        assert result.exit_code == 0
        downloaded = {(c.args[0].version, c.args[0].arch)
                      for c in mock_dl.call_args_list}
        assert downloaded == {("2.43", "amd64"), ("2.43", "i686")}


class TestMaybeDownloadSourceUnreadableDir:
    """An unreadable (e.g. root-owned 700) source dir must not crash the
    download loop — the source step is best-effort by contract."""

    @patch("pwnlibc.cli.source_present",
           side_effect=PermissionError("denied"))
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.downloader._fetch_index")
    def test_unreadable_source_dir_warns_not_crashes(
            self, mock_fetch, mock_dl, mock_present, runner, tmp_path):
        from tests.conftest import SAMPLE_MIRROR_HTML
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-dbg",
        ])
        assert result.exit_code == 0
        assert result.exception is None
        mock_dl.assert_called_once()  # the deb install itself succeeded
        assert "denied" in result.output  # surfaced as a Source: warning


class TestKeyringTildeExpansion:
    """--keyring ~/kr.gpg must expand like $PWNLIBC_KEYRING does."""

    def test_keyring_tilde_expanded(self, runner, tmp_path, monkeypatch):
        import os
        home = tmp_path / "home"
        home.mkdir()
        monkeypatch.setenv("HOME", str(home))

        with patch("pwnlibc.cli._run_signature_checks", return_value=True) as mock_sig, \
                patch("pwnlibc.cli.download_glibc"), \
                patch("pwnlibc.cli._scrape_mirrors",
                      return_value=[_mk_pkg("2.31-0ubuntu9.16_amd64")]):
            result = runner.invoke(cli, [
                "--glibc-dir", str(tmp_path),
                "download", "2.31", "--no-source", "--verify-signatures",
                "--keyring", "~/kr.gpg",
            ])
        assert result.exit_code == 0
        assert mock_sig.call_args[0][2] == home / "kr.gpg"
        assert str(mock_sig.call_args[0][2]).startswith(str(home))


class TestBuildTimeoutRange:
    """--timeout is documented as SECONDS with 0 = off; negatives are a
    usage error, not a silent cap-disabler."""

    def test_negative_timeout_rejected(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "build", "2.31", "--arch", "amd64", "--timeout", "-5",
        ])
        assert result.exit_code == 2  # click usage error
        assert "timeout" in result.output.lower()

    def test_zero_timeout_accepted(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        with patch("pwnlibc.builder.check_build_deps", return_value=[]):
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "build", "2.31", "--arch", "amd64", "--timeout", "0",
            ])
        assert result.exit_code != 2  # parsed fine (fails later on source)


class TestSignatureChecksUnmappedVersionNote:
    """--verify-signatures must not be silent for versions with no suite
    mapping: one yellow note per unique version, never a failure."""

    @patch("pwnlibc.cli.chown_tree", return_value=0)
    @patch("pwnlibc.cli.download_glibc")
    @patch("pwnlibc.cli._scrape_mirrors")
    def test_unmapped_version_gets_a_note_not_silence(
            self, mock_scrape, mock_dl, mock_chown, tmp_path):
        mock_scrape.return_value = [
            _mk_pkg("2.55-1ubuntu1_amd64"),
            _mk_pkg("2.55-1ubuntu1_i386", arch="i686"),
        ]
        result = CliRunner().invoke(cli, [
            "--glibc-dir", str(tmp_path),
            "download", "2.55", "--no-source", "--verify-signatures",
        ])
        assert result.exit_code == 0
        assert result.exception is None
        # one note per unique version, not one per (version, arch) package
        assert result.output.count(
            "2.55: no suite mapping — signature check not applicable") == 1
        assert "stale" in result.output  # tail of the wrapped parenthetical
        assert "FAIL" not in result.output


# ---------------------------------------------------------------------------
# setup --download: fetch prebuilt tarballs from debug_glibc without cloning
# ---------------------------------------------------------------------------

def _write_built_tarball(dest, version):
    """Write a real source-built-layout tarball to dest (as the fetch would)."""
    import io
    import tarfile
    names = [
        f"{version}/amd64/lib/libc-{version}.so",
        f"{version}/amd64/lib/libc.a",  # .a file -> detected as 'built'
    ]
    with tarfile.open(dest, "w:gz") as tf:
        for name in names:
            data = b"fake-elf-bytes" if name.endswith(".so") else b"fake-ar-bytes"
            info = tarfile.TarInfo(name=name)
            info.size = len(data)
            tf.addfile(info, io.BytesIO(data))


class TestSetupDownload:
    @patch("pwnlibc.cli.debug_glibc_fetch")
    def test_setup_download_installs_version(self, mock_fetch, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_fetch.side_effect = lambda version, dest: _write_built_tarball(dest, version)

        result = runner.invoke(cli, ["setup", "--download", "2.23",
                                     "--target-dir", str(glibc_dir)])

        assert result.exit_code == 0
        assert mock_fetch.call_args.args[0] == "2.23"
        assert (glibc_dir / "2.23" / "amd64-built" / "lib" /
                "libc-2.23.so").is_file()
        assert "2.23 done" in result.output
        assert "built" in result.output

    @patch("pwnlibc.cli.debug_glibc_fetch")
    def test_setup_download_fetch_failure_exits_1(self, mock_fetch, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        mock_fetch.side_effect = RuntimeError(
            "SHA256 mismatch for debug_glibc 9.99.tar.gz")

        result = runner.invoke(cli, ["setup", "--download", "9.99",
                                     "--target-dir", str(glibc_dir)])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "9.99" in result.output and "failed" in result.output

    @patch("pwnlibc.cli.debug_glibc_fetch")
    def test_setup_download_partial_failure_exits_0(self, mock_fetch, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fetch(version, dest):
            if version == "9.99":
                raise RuntimeError("not a Git-LFS pointer")
            _write_built_tarball(dest, version)
            return dest

        mock_fetch.side_effect = fetch
        result = runner.invoke(cli, ["setup", "--download", "9.99", "2.23",
                                     "--target-dir", str(glibc_dir)])

        assert result.exit_code == 0
        assert (glibc_dir / "2.23" / "amd64-built").is_dir()

    def test_setup_download_without_versions_is_usage_error(self, runner, tmp_path):
        result = runner.invoke(cli, ["setup", "--download",
                                     "--target-dir", str(tmp_path)])
        assert result.exit_code == 2

    def test_setup_without_dir_or_download_is_usage_error(self, runner):
        result = runner.invoke(cli, ["setup"])
        assert result.exit_code == 2
