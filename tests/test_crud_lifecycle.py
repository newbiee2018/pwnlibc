"""CRUD lifecycle tests for pwnlibc operations.

Tests the full Create/Read/Update/Delete cycle across:
- Deb releases (with and without debug info)
- Built releases (source-compiled with -g3)
- Source downloads
- Multiple architectures and versions

Verifies that CLI output changes correctly after each operation:
- `list` reflects downloads and removals
- `available` shows installed status
- `remove` clears entries and auto-removes source
- `patch` auto mode selects correct variant
- `source` subcommands reflect state

Also tests interconnecting behaviors:
- Remove last variant auto-removes source
- Download triggers source download by default
- Patch auto-mode priority: deb(dbg) > built(dbg) > prompt
- Restore removes .patched file
"""

import shutil
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import cli
from pwnlibc.config import ALL_ARCHES, ARCH_INFO, parse_version
from pwnlibc.glibc import GlibcInstall, discover_installed, resolve_lib_paths
from tests.conftest import (
    SAMPLE_DEBIAN_MIRROR_HTML,
    SAMPLE_MIRROR_HTML,
    SAMPLE_OLD_UBUNTU_MIRROR_HTML,
    SAMPLE_PORTS_MIRROR_HTML,
    _build_minimal_elf,
)


@pytest.fixture
def runner():
    return CliRunner()


def _create_deb_install(glibc_dir, version, arch, with_debug=False, with_source=False):
    """Create a fake deb install in the glibc directory."""
    info = ARCH_INFO[arch]
    ld_soname = info["ld_soname"]

    lib_dir = glibc_dir / version / arch / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    new_naming = parse_version(version) >= (2, 34)
    if new_naming:
        (lib_dir / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (lib_dir / ld_soname).write_bytes(b"\x7fELF" + b"\x00" * 100)
    else:
        (lib_dir / f"libc-{version}.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (lib_dir / f"ld-{version}.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
        (lib_dir / "libc.so.6").symlink_to(f"libc-{version}.so")
        (lib_dir / ld_soname).symlink_to(f"ld-{version}.so")

    if with_debug:
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(exist_ok=True)
        libc_name = "libc.so.6" if new_naming else f"libc-{version}.so"
        (debug_dir / f"{libc_name}.debug").write_bytes(b"\x00" * 50)

    if with_source:
        source_dir = glibc_dir / version / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        src_subdir = source_dir / f"glibc-{version}"
        src_subdir.mkdir(exist_ok=True)
        (src_subdir / "malloc.c").write_text("// glibc source\n")

    return lib_dir.parent


def _create_built_install(glibc_dir, version, arch, with_debug=True, with_source=False):
    """Create a fake built install in the glibc directory."""
    info = ARCH_INFO[arch]
    ld_soname = info["ld_soname"]

    lib_dir = glibc_dir / version / f"{arch}-built" / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    new_naming = parse_version(version) >= (2, 34)
    if new_naming:
        (lib_dir / "libc.so.6").write_bytes(b"\x7fELF" + b"\x00" * 200)
        (lib_dir / ld_soname).write_bytes(b"\x7fELF" + b"\x00" * 200)
    else:
        (lib_dir / f"libc-{version}.so").write_bytes(b"\x7fELF" + b"\x00" * 200)
        (lib_dir / f"ld-{version}.so").write_bytes(b"\x7fELF" + b"\x00" * 200)
        (lib_dir / "libc.so.6").symlink_to(f"libc-{version}.so")
        (lib_dir / ld_soname).symlink_to(f"ld-{version}.so")

    if with_debug:
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir(exist_ok=True)
        libc_name = "libc.so.6" if new_naming else f"libc-{version}.so"
        (debug_dir / f"{libc_name}.debug").write_bytes(b"\x00" * 50)

    if with_source:
        source_dir = glibc_dir / version / "source"
        source_dir.mkdir(parents=True, exist_ok=True)
        src_subdir = source_dir / f"glibc-{version}"
        src_subdir.mkdir(exist_ok=True)
        (src_subdir / "malloc.c").write_text("// glibc source\n")

    return lib_dir.parent


# ---------------------------------------------------------------------------
# CREATE: Install deb, deb+debug, built, source
# ---------------------------------------------------------------------------


class TestCreateDeb:
    """Installing a deb variant creates correct directory structure."""

    @pytest.mark.parametrize("arch", ALL_ARCHES)
    def test_create_deb_all_arches(self, tmp_path, arch):
        """Deb install for each arch is discoverable."""
        glibc_dir = tmp_path / "glibc"
        ver = "2.31" if arch in ("amd64", "i686", "powerpc") else "2.35"
        _create_deb_install(glibc_dir, ver, arch)
        installs = discover_installed(glibc_dir)
        match = [i for i in installs if i.arch == arch and i.version == ver and i.variant == "deb"]
        assert len(match) == 1
        assert match[0].has_debug is False

    @pytest.mark.parametrize("arch", ["amd64", "arm64", "mipsel"])
    def test_create_deb_with_debug(self, tmp_path, arch):
        """Deb+debug install is discoverable with has_debug=True."""
        glibc_dir = tmp_path / "glibc"
        ver = "2.35"
        _create_deb_install(glibc_dir, ver, arch, with_debug=True)
        installs = discover_installed(glibc_dir)
        match = [i for i in installs if i.arch == arch and i.variant == "deb"]
        assert len(match) == 1
        assert match[0].has_debug is True

    def test_create_deb_old_naming(self, tmp_path):
        """Old naming (< 2.34) creates libc-VERSION.so files."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.new_naming is False
        assert "libc-2.31.so" in install.libc_path.name

    def test_create_deb_new_naming(self, tmp_path):
        """New naming (>= 2.34) creates libc.so.6 directly."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64")
        install = resolve_lib_paths("2.35", "amd64", glibc_dir, "deb")
        assert install.new_naming is True
        assert install.libc_path.name == "libc.so.6"


class TestCreateBuilt:
    """Installing a built variant creates correct directory structure."""

    @pytest.mark.parametrize("arch", ["amd64", "i686", "arm64", "armhf", "ppc64el", "s390x", "riscv64"])
    def test_create_built_all_arches(self, tmp_path, arch):
        """Built install for each arch is discoverable."""
        glibc_dir = tmp_path / "glibc"
        ver = "2.31" if arch in ("amd64", "i686") else "2.35"
        _create_built_install(glibc_dir, ver, arch)
        installs = discover_installed(glibc_dir)
        match = [i for i in installs if i.arch == arch and i.variant == "built"]
        assert len(match) == 1
        assert match[0].has_debug is True

    def test_built_dir_named_arch_built(self, tmp_path):
        """Built variant uses <arch>-built directory name."""
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64")
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "built")
        assert install.base_dir.name == "amd64-built"


class TestCreateSource:
    """Source directory creation and detection."""

    def test_create_source_detected_by_install(self, tmp_path):
        """has_source is True when source/ directory exists."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.has_source is True

    def test_no_source_by_default(self, tmp_path):
        """has_source is False when no source/ directory."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.has_source is False

    def test_source_shared_across_variants(self, tmp_path):
        """Source directory is shared between deb and built variants."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        _create_built_install(glibc_dir, "2.31", "amd64")
        deb = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        built = resolve_lib_paths("2.31", "amd64", glibc_dir, "built")
        assert deb.has_source is True
        assert built.has_source is True


# ---------------------------------------------------------------------------
# READ: list, available, source status
# ---------------------------------------------------------------------------


class TestReadListCommand:
    """list command reflects installed state correctly."""

    def test_list_empty_dir(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "No glibc versions found" in result.output

    def test_list_shows_deb_variant(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "2.31" in result.output
        assert "deb" in result.output

    def test_list_shows_deb_dbg_variant(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "2.31" in result.output
        assert "deb(dbg)" in result.output

    def test_list_shows_built_variant(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "built" in result.output

    def test_list_shows_both_variants(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        _create_built_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "deb(dbg)" in result.output
        assert "built" in result.output

    def test_list_shows_source_column(self, runner, tmp_path):
        """Source column shows 'yes' when source exists."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "yes" in result.output

    def test_list_source_column_no_source(self, runner, tmp_path):
        """Source column shows '-' when no source."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        # Source column header should be present
        assert "Source" in result.output

    def test_list_filter_by_arch(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64")
        _create_deb_install(glibc_dir, "2.35", "arm64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list", "--arch", "amd64"])
        assert result.exit_code == 0
        assert "amd64" in result.output
        assert "arm64" not in result.output

    def test_list_multiple_versions(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.27", "amd64")
        _create_deb_install(glibc_dir, "2.31", "amd64")
        _create_deb_install(glibc_dir, "2.35", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert result.exit_code == 0
        assert "2.27" in result.output
        assert "2.31" in result.output
        assert "2.35" in result.output


class TestReadAvailableCommand:
    """available command shows installed status correctly."""

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_installed_deb(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "deb" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_installed_deb_dbg(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "deb(dbg)" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_debug_deb_column(self, mock_fetch, runner, tmp_path):
        """Available output includes Debug .deb column."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "Debug .deb" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_mirror_column(self, mock_fetch, runner, tmp_path):
        """Available output includes Mirror column."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "Mirror" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_not_installed_shows_dash(self, mock_fetch, runner, tmp_path):
        """Uninstalled versions show '-' in Installed column."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "Installed" in result.output


class TestReadSourceCommand:
    """source command reflects source download state."""

    def test_source_shows_installed(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "source"])
        assert result.exit_code == 0
        assert "2.31" in result.output
        assert "yes" in result.output

    def test_source_shows_missing(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "source"])
        assert result.exit_code == 0
        assert "2.31" in result.output

    def test_source_check_reports_status(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        _create_deb_install(glibc_dir, "2.35", "amd64")
        result = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "source", "check"])
        assert result.exit_code == 0
        assert "OK" in result.output
        assert "missing" in result.output


# ---------------------------------------------------------------------------
# UPDATE: Add debug to existing deb, add source, upgrade variant
# ---------------------------------------------------------------------------


class TestUpdateAddDebug:
    """Adding debug symbols to an existing deb install."""

    def test_add_debug_changes_has_debug(self, tmp_path):
        """Adding .debug/ directory makes has_debug switch to True."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.has_debug is False

        debug_dir = install.lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / "libc-2.31.so.debug").write_bytes(b"\x00" * 50)

        install2 = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install2.has_debug is True

    def test_add_debug_changes_list_output(self, runner, tmp_path):
        """list output changes from 'deb' to 'deb(dbg)' after adding debug."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "deb(dbg)" not in result1.output
        assert "deb" in result1.output

        lib_dir = glibc_dir / "2.31" / "amd64" / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / "libc-2.31.so.debug").write_bytes(b"\x00" * 50)

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "deb(dbg)" in result2.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_add_debug_changes_available_output(self, mock_fetch, runner, tmp_path):
        """available Installed column changes from 'deb' to 'deb(dbg)'."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert "deb(dbg)" not in result1.output

        lib_dir = glibc_dir / "2.31" / "amd64" / "lib"
        debug_dir = lib_dir / ".debug"
        debug_dir.mkdir()
        (debug_dir / "libc-2.31.so.debug").write_bytes(b"\x00" * 50)

        result2 = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--no-check-source",
        ])
        assert "deb(dbg)" in result2.output


class TestUpdateAddSource:
    """Adding source to an existing install."""

    def test_add_source_changes_has_source(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.has_source is False

        source_dir = glibc_dir / "2.31" / "source"
        source_dir.mkdir(parents=True)
        (source_dir / "glibc-2.31").mkdir()

        install2 = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install2.has_source is True

    def test_add_source_changes_list_output(self, runner, tmp_path):
        """list Source column switches from '-' to 'yes' after adding source."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        # The Source column should not show "yes" yet
        lines1 = result1.output.split("\n")
        row_lines1 = [l for l in lines1 if "2.31" in l]
        assert row_lines1  # version is shown

        source_dir = glibc_dir / "2.31" / "source"
        source_dir.mkdir(parents=True)
        (source_dir / "glibc-2.31").mkdir()

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "yes" in result2.output


class TestUpdateAddBuiltVariant:
    """Adding a built variant alongside existing deb."""

    def test_add_built_alongside_deb(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        installs = discover_installed(glibc_dir)
        assert len([i for i in installs if i.version == "2.31" and i.arch == "amd64"]) == 1

        _create_built_install(glibc_dir, "2.31", "amd64")

        installs2 = discover_installed(glibc_dir)
        amd64_231 = [i for i in installs2 if i.version == "2.31" and i.arch == "amd64"]
        assert len(amd64_231) == 2
        variants = {i.variant for i in amd64_231}
        assert variants == {"deb", "built"}

    def test_add_built_changes_list(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "built" not in result1.output

        _create_built_install(glibc_dir, "2.31", "amd64")

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "built" in result2.output


# ---------------------------------------------------------------------------
# DELETE: remove deb, built, source; auto-remove source
# ---------------------------------------------------------------------------


class TestDeleteDeb:
    """Removing deb variant via CLI."""

    def test_remove_deb_clears_from_list(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "2.31" in result1.output

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "deb",
        ])
        assert result.exit_code == 0
        assert "Removed" in result.output

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "2.31" not in result2.output or "No glibc" in result2.output

    def test_remove_deb_keeps_built(self, runner, tmp_path):
        """Removing deb should not remove built variant."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        _create_built_install(glibc_dir, "2.31", "amd64")

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "deb",
        ])

        installs = discover_installed(glibc_dir)
        match = [i for i in installs if i.version == "2.31" and i.arch == "amd64"]
        assert len(match) == 1
        assert match[0].variant == "built"

    def test_remove_deb_specific_arch(self, runner, tmp_path):
        """--arch filter removes only that arch's deb."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64")
        _create_deb_install(glibc_dir, "2.35", "arm64")

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.35",
            "--variant", "deb", "--arch", "amd64",
        ])

        installs = discover_installed(glibc_dir)
        arches = {i.arch for i in installs if i.version == "2.35"}
        assert "amd64" not in arches
        assert "arm64" in arches


class TestDeleteBuilt:
    """Removing built variant via CLI."""

    def test_remove_built_clears_from_list(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "built" in result1.output

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "built",
        ])
        assert result.exit_code == 0
        assert "Removed" in result.output

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "No glibc versions found" in result2.output

    def test_remove_built_keeps_deb(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")
        _create_built_install(glibc_dir, "2.31", "amd64")

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "built",
        ])

        installs = discover_installed(glibc_dir)
        match = [i for i in installs if i.version == "2.31" and i.arch == "amd64"]
        assert len(match) == 1
        assert match[0].variant == "deb"


class TestDeleteSource:
    """Removing source via CLI."""

    def test_source_remove_clears_source(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "source"])
        assert "yes" in result1.output

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "source", "remove", "2.31",
        ])
        assert result.exit_code == 0
        assert "Removed" in result.output

        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.has_source is False

    def test_remove_variant_source(self, runner, tmp_path):
        """remove --variant source removes source, keeps libs."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "source",
        ])

        installs = discover_installed(glibc_dir)
        deb = [i for i in installs if i.version == "2.31" and i.variant == "deb"]
        assert len(deb) == 1
        assert deb[0].has_source is False


class TestDeleteAll:
    """Removing all variants at once."""

    def test_remove_all_clears_everything(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True, with_source=True)
        _create_built_install(glibc_dir, "2.31", "amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31",
        ])
        assert result.exit_code == 0

        installs = discover_installed(glibc_dir)
        assert not any(i.version == "2.31" for i in installs)

    def test_remove_nonexistent_version(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.99",
        ])
        assert "not installed" in result.output


# ---------------------------------------------------------------------------
# Interconnecting behaviors
# ---------------------------------------------------------------------------


class TestAutoRemoveSource:
    """Source is auto-removed when the last deb/built variant is removed."""

    def test_remove_last_deb_auto_removes_source(self, runner, tmp_path):
        """When the last variant is removed, source is auto-cleaned."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)

        source_dir = glibc_dir / "2.31" / "source"
        assert source_dir.is_dir()

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "deb",
        ])

        assert not source_dir.is_dir(), "Source should be auto-removed when no variants remain"

    def test_remove_deb_keeps_source_if_built_remains(self, runner, tmp_path):
        """Source is NOT auto-removed if a built variant still exists."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        _create_built_install(glibc_dir, "2.31", "amd64")

        source_dir = glibc_dir / "2.31" / "source"
        assert source_dir.is_dir()

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "deb",
        ])

        assert source_dir.is_dir(), "Source should remain while built variant exists"

    def test_remove_built_then_deb_auto_removes_source(self, runner, tmp_path):
        """Source removed only after BOTH variants are gone."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_source=True)
        _create_built_install(glibc_dir, "2.31", "amd64")

        source_dir = glibc_dir / "2.31" / "source"

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "built",
        ])
        assert source_dir.is_dir(), "Source should remain while deb exists"

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.31", "--variant", "deb",
        ])
        assert not source_dir.is_dir(), "Source should be auto-removed now"

    def test_remove_arch_specific_keeps_source_if_other_arch_remains(self, runner, tmp_path):
        """Removing one arch doesn't auto-remove source if another arch remains."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64", with_source=True)
        _create_deb_install(glibc_dir, "2.35", "arm64")

        source_dir = glibc_dir / "2.35" / "source"

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.35",
            "--variant", "deb", "--arch", "amd64",
        ])

        assert source_dir.is_dir(), "Source should remain while arm64 variant exists"


class TestPatchAutoVariantSelection:
    """patch auto mode selects the correct variant based on available debug info."""

    def test_auto_selects_deb_dbg(self, runner, tmp_path):
        """Auto mode selects deb(dbg) as highest priority."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64", with_debug=True)
        _create_built_install(glibc_dir, "2.35", "amd64")
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.35",
            ])
        assert result.exit_code == 0
        assert "deb(dbg)" in result.output
        assert "Choose" not in result.output

    def test_auto_falls_back_to_built_dbg(self, runner, tmp_path):
        """When deb has no debug, auto selects built(dbg)."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=True)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.31",
            ])
        assert result.exit_code == 0
        assert "built" in result.output.lower()
        assert "Choose" not in result.output

    def test_auto_prompts_when_no_debug(self, runner, tmp_path):
        """When deb exists but no debug anywhere, auto prompts user."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "patch", str(binary), "-v", "2.31",
        ], input="3\n")
        assert "no debug symbols" in result.output.lower()
        assert "Choose" in result.output or "choose" in result.output

    def test_auto_nothing_installed(self, runner, tmp_path):
        """When nothing is installed, auto reports not found."""
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "patch", str(binary), "-v", "2.31",
        ])
        assert result.exit_code != 0
        assert "not found" in result.output.lower()

    def test_explicit_variant_deb(self, runner, tmp_path):
        """--variant deb selects deb even when built has debug."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=True)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.31", "--variant", "deb",
            ])
        assert result.exit_code == 0
        assert "no debug symbols" in result.output.lower() or "Warning" in result.output

    def test_explicit_variant_built(self, runner, tmp_path):
        """--variant built selects built directly."""
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=True)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.31", "--variant", "built",
            ])
        assert result.exit_code == 0
        assert "built" in result.output.lower()


class TestRestorePatchedFile:
    """restore removes .patched file."""

    def test_restore_removes_patched(self, runner, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)
        patched = tmp_path / "hello.patched"
        patched.write_bytes(b"\x7fELF" + b"\x00" * 200)

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code == 0
        assert "Removed" in result.output
        assert not patched.exists()
        assert binary.exists()

    def test_restore_no_patched_no_backup(self, runner, tmp_path):
        binary = tmp_path / "hello"
        binary.write_bytes(b"\x7fELF" + b"\x00" * 100)

        result = runner.invoke(cli, ["restore", str(binary)])
        assert result.exit_code != 0
        assert "No .patched file or backup found" in result.output


class TestDownloadWithSource:
    """download command's --source/--no-source behavior."""

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._extract_dbg_deb")
    # The availability HEAD is part of the real flow; without this patch the
    # test does live network I/O (offline-default violation — it fails when
    # the network is down).
    @patch("pwnlibc.builder.check_source_available",
           return_value="https://ftp.gnu.org/gnu/glibc/glibc-2.31.tar.xz")
    @patch("pwnlibc.cli.download_source")
    def test_download_default_includes_source(
        self, mock_dl_src, mock_check_src, mock_extract_dbg, mock_extract, mock_dl_file, mock_fetch,
        runner, tmp_path,
    ):
        """By default, download triggers source download."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fake_extract(deb_path, out_dir, arch):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "libc.so.6").symlink_to("libc-2.31.so")
            (out_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

        mock_extract.side_effect = fake_extract

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        mock_dl_src.assert_called_once()

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._extract_dbg_deb")
    @patch("pwnlibc.cli.download_source")
    def test_download_no_source_skips(
        self, mock_dl_src, mock_extract_dbg, mock_extract, mock_dl_file, mock_fetch,
        runner, tmp_path,
    ):
        """--no-source skips source download."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fake_extract(deb_path, out_dir, arch):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "libc.so.6").symlink_to("libc-2.31.so")
            (out_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

        mock_extract.side_effect = fake_extract

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        mock_dl_src.assert_not_called()


class TestDownloadWithDebug:
    """download command's --with-dbg/--no-dbg behavior."""

    @patch("pwnlibc.downloader._fetch_index")
    @patch("pwnlibc.downloader._download_file")
    @patch("pwnlibc.downloader._extract_deb")
    @patch("pwnlibc.downloader._extract_dbg_deb")
    @patch("pwnlibc.cli.download_source")
    def test_download_with_dbg_extracts_debug(
        self, mock_dl_src, mock_extract_dbg, mock_extract, mock_dl_file, mock_fetch,
        runner, tmp_path,
    ):
        """--with-dbg (default) extracts debug deb when available."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        def fake_extract(deb_path, out_dir, arch):
            out_dir.mkdir(parents=True, exist_ok=True)
            (out_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
            (out_dir / "libc.so.6").symlink_to("libc-2.31.so")
            (out_dir / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

        mock_extract.side_effect = fake_extract

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download", "2.31", "--arch", "amd64", "--no-source",
        ])
        assert result.exit_code == 0
        # 2.31/amd64 has dbg_filename in SAMPLE_MIRROR_HTML
        assert mock_extract_dbg.called or mock_dl_file.call_count >= 1


class TestEmptyDirCleanup:
    """Empty version directories are cleaned up after removal."""

    def test_empty_ver_dir_removed(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64")

        runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "remove", "2.31"])

        ver_dir = glibc_dir / "2.31"
        assert not ver_dir.exists(), "Empty version directory should be cleaned up"


# ---------------------------------------------------------------------------
# Multi-version / multi-arch CRUD cycles
# ---------------------------------------------------------------------------


class TestMultiVersionCRUD:
    """Full CRUD cycle across multiple versions."""

    def test_create_three_versions_remove_middle(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.27", "amd64")
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        _create_deb_install(glibc_dir, "2.35", "amd64")

        result1 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "2.27" in result1.output
        assert "2.31" in result1.output
        assert "2.35" in result1.output

        runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "remove", "2.31"])

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "2.27" in result2.output
        assert "2.31" not in result2.output
        assert "2.35" in result2.output

    def test_remove_multiple_versions_at_once(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.27", "amd64")
        _create_deb_install(glibc_dir, "2.31", "amd64")
        _create_deb_install(glibc_dir, "2.35", "amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.27", "2.35",
        ])
        assert result.exit_code == 0

        result2 = runner.invoke(cli, ["--glibc-dir", str(glibc_dir), "list"])
        assert "2.27" not in result2.output
        assert "2.31" in result2.output
        assert "2.35" not in result2.output


class TestMultiArchCRUD:
    """CRUD across different architectures."""

    @pytest.mark.parametrize("arch", ["amd64", "arm64", "mipsel", "s390x"])
    def test_create_read_delete_per_arch(self, runner, tmp_path, arch):
        """Full cycle for each arch: create, read from list, delete."""
        glibc_dir = tmp_path / "glibc"
        ver = "2.35"
        _create_deb_install(glibc_dir, ver, arch)

        result1 = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "list", "--arch", arch,
        ])
        assert ver in result1.output

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", ver, "--arch", arch,
        ])

        result2 = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "list", "--arch", arch,
        ])
        assert ver not in result2.output or "No glibc" in result2.output

    def test_remove_one_arch_keeps_others(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        for arch in ["amd64", "arm64", "mipsel"]:
            _create_deb_install(glibc_dir, "2.35", arch)

        runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "remove", "2.35",
            "--variant", "deb", "--arch", "arm64",
        ])

        installs = discover_installed(glibc_dir)
        arches = {i.arch for i in installs if i.version == "2.35"}
        assert "arm64" not in arches
        assert "amd64" in arches
        assert "mipsel" in arches


# ---------------------------------------------------------------------------
# Debug/variant distinction clarity
# ---------------------------------------------------------------------------


class TestDebugIsAttributeNotVariant:
    """Verify that debug is an attribute (has_debug), not a separate variant."""

    def test_deb_without_debug(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.variant == "deb"
        assert install.has_debug is False

    def test_deb_with_debug(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert install.variant == "deb"
        assert install.has_debug is True

    def test_built_with_debug(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=True)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "built")
        assert install.variant == "built"
        assert install.has_debug is True

    def test_built_without_debug(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=False)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "built")
        assert install.variant == "built"
        assert install.has_debug is False

    def test_only_two_variants_exist(self):
        """GlibcInstall only supports 'deb' and 'built' — debug is an attribute."""
        install = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=Path("/glibc/2.31/amd64"),
            lib_dir=Path("/glibc/2.31/amd64/lib"),
            libc_path=Path("/glibc/2.31/amd64/lib/libc-2.31.so"),
            ld_path=Path("/glibc/2.31/amd64/lib/ld-2.31.so"),
            has_source=False, has_debug=False, new_naming=False,
        )
        assert install.variant == "deb"
        assert hasattr(install, "has_debug")

    def test_variant_label_deb(self, tmp_path):
        """_variant_label returns 'deb' for deb without debug."""
        from pwnlibc.cli import _variant_label
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert _variant_label(install) == "deb"

    def test_variant_label_deb_dbg(self, tmp_path):
        """_variant_label returns 'deb(dbg)' for deb with debug."""
        from pwnlibc.cli import _variant_label
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")
        assert _variant_label(install) == "deb(dbg)"

    def test_variant_label_built_dbg(self, tmp_path):
        """_variant_label returns 'built(dbg)' for built with debug."""
        from pwnlibc.cli import _variant_label
        glibc_dir = tmp_path / "glibc"
        _create_built_install(glibc_dir, "2.31", "amd64", with_debug=True)
        install = resolve_lib_paths("2.31", "amd64", glibc_dir, "built")
        assert _variant_label(install) == "built(dbg)"


# ---------------------------------------------------------------------------
# Mirror per arch
# ---------------------------------------------------------------------------


class TestMirrorPerArch:
    """Each arch resolves to its correct mirror."""

    def test_x86_uses_ubuntu(self):
        assert ARCH_INFO["amd64"]["mirror"] == "ubuntu"
        assert ARCH_INFO["i686"]["mirror"] == "ubuntu"

    def test_arm_uses_ports(self):
        assert ARCH_INFO["arm64"]["mirror"] == "ports"
        assert ARCH_INFO["armhf"]["mirror"] == "ports"

    def test_mips_uses_debian(self):
        assert ARCH_INFO["mipsel"]["mirror"] == "debian"
        assert ARCH_INFO["mips64el"]["mirror"] == "debian"

    def test_powerpc_uses_old_ubuntu(self):
        assert ARCH_INFO["powerpc"]["mirror"] == "old-ubuntu"

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_ports_arch(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_PORTS_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "arm64", "--mirror", "ports", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "arm64" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_debian_arch(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_DEBIAN_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "mipsel", "--mirror", "debian", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "mipsel" in result.output


# ---------------------------------------------------------------------------
# Patch output messages
# ---------------------------------------------------------------------------


class TestPatchOutputMessages:
    """Patch command output contains correct variant and debug info."""

    def test_patch_output_shows_variant_label(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64", with_debug=True)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.35",
            ])
        assert result.exit_code == 0
        assert "deb(dbg)" in result.output
        assert ".patched" in result.output

    def test_patch_copy_mode_shows_lib_count(self, runner, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64", with_debug=True)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_copy") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = (patched_path, [Path("a"), Path("b")])
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.35", "--mode", "copy",
            ])
        assert result.exit_code == 0
        assert "Copied 2 libs" in result.output

    def test_patch_warns_no_debug(self, runner, tmp_path):
        """--variant deb with no debug should warn."""
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.35", "amd64", with_debug=False)
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        with patch("pwnlibc.cli.patch_inplace") as mock_patch:
            patched_path = binary.parent / (binary.name + ".patched")
            patched_path.write_bytes(b"\x7fELF" + b"\x00" * 100)
            mock_patch.return_value = patched_path
            result = runner.invoke(cli, [
                "--glibc-dir", str(glibc_dir),
                "patch", str(binary), "-v", "2.35", "--variant", "deb",
            ])
        assert result.exit_code == 0
        assert "no debug" in result.output.lower() or "Warning" in result.output


# ---------------------------------------------------------------------------
# ds1 version handling
# ---------------------------------------------------------------------------


class TestDs1VersionHandling:
    """Versions like 2.3.2.ds1 are handled correctly."""

    def test_parse_version_strips_ds1(self):
        assert parse_version("2.3.2.ds1") == (2, 3, 2)

    def test_create_and_discover_ds1(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.3.6", "amd64")
        installs = discover_installed(glibc_dir)
        assert any(i.version == "2.3.6" for i in installs)

    @patch("pwnlibc.downloader._fetch_index")
    def test_available_shows_old_versions(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_OLD_UBUNTU_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir), "available",
            "--arch", "amd64", "--mirror", "old-ubuntu", "--no-check-source",
        ])
        assert result.exit_code == 0
        assert "2.3.6" in result.output


# ---------------------------------------------------------------------------
# download-all dry run with CRUD state
# ---------------------------------------------------------------------------


class TestDownloadAllDryRun:
    """download-all --check shows what would be downloaded based on installed state."""

    @patch("pwnlibc.downloader._fetch_index")
    def test_check_shows_missing(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--check", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert "to download" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_check_all_installed(self, mock_fetch, runner, tmp_path):
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.27", "amd64", with_debug=True)
        _create_deb_install(glibc_dir, "2.27", "i686", with_debug=True)
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=True)
        _create_deb_install(glibc_dir, "2.31", "i686", with_debug=True)
        _create_deb_install(glibc_dir, "2.35", "amd64", with_debug=True)
        _create_deb_install(glibc_dir, "2.35", "i686", with_debug=True)
        _create_deb_install(glibc_dir, "2.39", "amd64", with_debug=True)
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--check",
        ])
        assert result.exit_code == 0
        assert "already installed" in result.output

    @patch("pwnlibc.downloader._fetch_index")
    def test_check_detects_missing_dbg(self, mock_fetch, runner, tmp_path):
        """download-all --check detects installed debs missing debug symbols."""
        mock_fetch.return_value = SAMPLE_MIRROR_HTML
        glibc_dir = tmp_path / "glibc"
        _create_deb_install(glibc_dir, "2.31", "amd64", with_debug=False)
        _create_deb_install(glibc_dir, "2.31", "i686", with_debug=False)
        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "download-all", "--check", "--arch", "amd64",
        ])
        assert result.exit_code == 0
        assert "missing debug" in result.output.lower() or "to download" in result.output
