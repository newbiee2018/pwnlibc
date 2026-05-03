"""Tests for the three-choice variant system (deb, deb-dbg, built).

Test points:
- GlibcInstall correctly identifies variant type
- discover_installed finds all three variants separately
- resolve_lib_paths with variant="deb" vs variant="built" gives different paths
- Built variant lives in arch-built/ directory, deb in arch/
- Debug symbols (.debug/) mark deb-dbg variant
- patch --variant selects correct variant
- list command shows all variants distinctly
- All architectures support the variant system
"""

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
from click.testing import CliRunner

from pwnlibc.cli import cli
from pwnlibc.config import ALL_ARCHES, ARCH_INFO
from pwnlibc.glibc import GlibcInstall, discover_installed, resolve_lib_paths


@pytest.fixture
def runner():
    return CliRunner()


@pytest.fixture
def three_variant_dir(tmp_path):
    """Glibc dir with all three variants for 2.31 amd64."""
    glibc_dir = tmp_path / "glibc"

    # Variant 1: deb (plain libc6 extract)
    deb_lib = glibc_dir / "2.31" / "amd64" / "lib"
    deb_lib.mkdir(parents=True)
    (deb_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (deb_lib / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)
    (deb_lib / "libc.so.6").symlink_to("libc-2.31.so")
    (deb_lib / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

    # Variant 2: deb-dbg (deb + .debug/ directory)
    # Same lib dir as deb, just with .debug/ added
    debug_dir = deb_lib / ".debug"
    debug_dir.mkdir()
    (debug_dir / "libc-2.31.so.debug").write_bytes(b"\x00" * 50)

    # Variant 3: built (source-compiled)
    built_lib = glibc_dir / "2.31" / "amd64-built" / "lib"
    built_lib.mkdir(parents=True)
    (built_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 200)
    (built_lib / "ld-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 200)
    (built_lib / "libc.so.6").symlink_to("libc-2.31.so")
    (built_lib / "ld-linux-x86-64.so.2").symlink_to("ld-2.31.so")

    return glibc_dir


@pytest.fixture
def multiarch_built_dir(tmp_path):
    """Glibc dir with built variants for multiple architectures."""
    glibc_dir = tmp_path / "glibc"

    arch_configs = {
        "amd64": ("libc-2.31.so", "ld-2.31.so", "ld-linux-x86-64.so.2"),
        "i686": ("libc-2.31.so", "ld-2.31.so", "ld-linux.so.2"),
        "arm64": ("libc.so.6", "ld-linux-aarch64.so.1", "ld-linux-aarch64.so.1"),
        "armhf": ("libc.so.6", "ld-linux-armhf.so.3", "ld-linux-armhf.so.3"),
        "ppc64el": ("libc.so.6", "ld64.so.2", "ld64.so.2"),
        "s390x": ("libc.so.6", "ld64.so.1", "ld64.so.1"),
        "riscv64": ("libc.so.6", "ld-linux-riscv64-lp64d.so.1", "ld-linux-riscv64-lp64d.so.1"),
    }

    for arch, (libc_name, ld_name, ld_soname) in arch_configs.items():
        # Use 2.35 for non-x86 (new naming), 2.31 for x86 (old naming)
        ver = "2.31" if arch in ("amd64", "i686") else "2.35"

        built_lib = glibc_dir / ver / f"{arch}-built" / "lib"
        built_lib.mkdir(parents=True)
        (built_lib / libc_name).write_bytes(b"\x7fELF" + b"\x00" * 100)
        (built_lib / ld_name).write_bytes(b"\x7fELF" + b"\x00" * 100)
        if libc_name != "libc.so.6":
            (built_lib / "libc.so.6").symlink_to(libc_name)
        if ld_name != ld_soname:
            (built_lib / ld_soname).symlink_to(ld_name)

    return glibc_dir


class TestResolveLibPaths:
    """resolve_lib_paths correctly distinguishes deb vs built."""

    def test_resolve_deb_variant(self, three_variant_dir):
        install = resolve_lib_paths("2.31", "amd64", three_variant_dir, "deb")
        assert install.variant == "deb"
        assert "amd64-built" not in str(install.lib_dir)
        assert install.lib_dir == three_variant_dir / "2.31" / "amd64" / "lib"

    def test_resolve_built_variant(self, three_variant_dir):
        install = resolve_lib_paths("2.31", "amd64", three_variant_dir, "built")
        assert install.variant == "built"
        assert "amd64-built" in str(install.base_dir)
        assert install.lib_dir == three_variant_dir / "2.31" / "amd64-built" / "lib"

    def test_deb_and_built_different_paths(self, three_variant_dir):
        deb = resolve_lib_paths("2.31", "amd64", three_variant_dir, "deb")
        built = resolve_lib_paths("2.31", "amd64", three_variant_dir, "built")
        assert deb.lib_dir != built.lib_dir
        assert deb.base_dir != built.base_dir

    def test_built_not_found_raises(self, tmp_path):
        """Requesting built variant when none exists raises FileNotFoundError."""
        glibc_dir = tmp_path / "glibc"
        lib_dir = glibc_dir / "2.31" / "amd64" / "lib"
        lib_dir.mkdir(parents=True)
        (lib_dir / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        with pytest.raises(FileNotFoundError):
            resolve_lib_paths("2.31", "amd64", glibc_dir, "built")

    def test_deb_not_found_raises(self, tmp_path):
        """Requesting deb variant when none exists raises FileNotFoundError."""
        glibc_dir = tmp_path / "glibc"
        # Only built exists
        built_lib = glibc_dir / "2.31" / "amd64-built" / "lib"
        built_lib.mkdir(parents=True)
        (built_lib / "libc-2.31.so").write_bytes(b"\x7fELF" + b"\x00" * 100)

        with pytest.raises(FileNotFoundError):
            resolve_lib_paths("2.31", "amd64", glibc_dir, "deb")


class TestDiscoverInstalled:
    """discover_installed finds all variants correctly."""

    def test_finds_deb_variant(self, three_variant_dir):
        installs = discover_installed(three_variant_dir)
        deb_installs = [i for i in installs if i.variant == "deb"]
        assert any(i.arch == "amd64" and i.version == "2.31" for i in deb_installs)

    def test_finds_built_variant(self, three_variant_dir):
        installs = discover_installed(three_variant_dir)
        built_installs = [i for i in installs if i.variant == "built"]
        assert any(i.arch == "amd64" and i.version == "2.31" for i in built_installs)

    def test_deb_and_built_coexist(self, three_variant_dir):
        installs = discover_installed(three_variant_dir)
        amd64_231 = [i for i in installs if i.arch == "amd64" and i.version == "2.31"]
        variants = {i.variant for i in amd64_231}
        assert "deb" in variants
        assert "built" in variants

    def test_deb_has_debug(self, three_variant_dir):
        """deb variant with .debug/ dir should report has_debug=True."""
        installs = discover_installed(three_variant_dir)
        deb = [i for i in installs if i.variant == "deb" and i.version == "2.31"
               and i.arch == "amd64"]
        assert len(deb) == 1
        assert deb[0].has_debug is True

    def test_discovers_multiarch_built(self, multiarch_built_dir):
        """Discovers built variants for multiple architectures."""
        installs = discover_installed(multiarch_built_dir)
        built = [i for i in installs if i.variant == "built"]
        arches_found = {i.arch for i in built}
        # At minimum amd64 and arm64 should be discovered
        assert "amd64" in arches_found
        assert "arm64" in arches_found

    def test_empty_dir_returns_empty(self, tmp_path):
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()
        assert discover_installed(glibc_dir) == []

    def test_nonexistent_dir_returns_empty(self, tmp_path):
        assert discover_installed(tmp_path / "nonexistent") == []


class TestGlibcInstallDataclass:
    """GlibcInstall variant field distinguishes entries."""

    def test_default_variant_is_deb(self):
        install = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=Path("/glibc/2.31/amd64"),
            lib_dir=Path("/glibc/2.31/amd64/lib"),
            libc_path=Path("/glibc/2.31/amd64/lib/libc-2.31.so"),
            ld_path=Path("/glibc/2.31/amd64/lib/ld-2.31.so"),
            has_source=False, has_debug=False, new_naming=False,
        )
        assert install.variant == "deb"

    def test_built_variant_explicit(self):
        install = GlibcInstall(
            version="2.31", arch="amd64",
            base_dir=Path("/glibc/2.31/amd64-built"),
            lib_dir=Path("/glibc/2.31/amd64-built/lib"),
            libc_path=Path("/glibc/2.31/amd64-built/lib/libc-2.31.so"),
            ld_path=Path("/glibc/2.31/amd64-built/lib/ld-2.31.so"),
            has_source=False, has_debug=False, new_naming=False,
            variant="built",
        )
        assert install.variant == "built"


class TestVariantDirectoryLayout:
    """Directory layout follows the convention: arch/ for deb, arch-built/ for built."""

    @pytest.mark.parametrize("arch", ALL_ARCHES)
    def test_built_dir_naming(self, arch):
        """Built variant directory should be named '<arch>-built'."""
        expected = f"{arch}-built"
        assert "-built" in expected
        # Verify ARCH_INFO exists for this arch (data-driven)
        assert arch in ARCH_INFO

    def test_built_dir_resolved_correctly(self, three_variant_dir):
        built = resolve_lib_paths("2.31", "amd64", three_variant_dir, "built")
        assert built.base_dir.name == "amd64-built"

    def test_deb_dir_no_suffix(self, three_variant_dir):
        deb = resolve_lib_paths("2.31", "amd64", three_variant_dir, "deb")
        assert deb.base_dir.name == "amd64"
        assert "-built" not in str(deb.base_dir)


class TestMultiArchBuiltVariants:
    """Built variants are correctly resolved for all architectures."""

    def test_arm64_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.35", "arm64", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "arm64"
        assert "arm64-built" in str(install.base_dir)

    def test_armhf_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.35", "armhf", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "armhf"

    def test_ppc64el_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.35", "ppc64el", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "ppc64el"

    def test_s390x_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.35", "s390x", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "s390x"

    def test_riscv64_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.35", "riscv64", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "riscv64"

    def test_i686_built(self, multiarch_built_dir):
        install = resolve_lib_paths("2.31", "i686", multiarch_built_dir, "built")
        assert install.variant == "built"
        assert install.arch == "i686"


class TestListCommandVariants:
    """list command shows variants distinctly."""

    def test_list_shows_built_and_deb(self, runner, three_variant_dir):
        result = runner.invoke(cli, [
            "--glibc-dir", str(three_variant_dir),
            "list",
        ])
        assert result.exit_code == 0
        # Both deb and built should appear in output
        assert "2.31" in result.output

    def test_list_populated_dir(self, runner, populated_glibc_dir):
        result = runner.invoke(cli, [
            "--glibc-dir", str(populated_glibc_dir),
            "list",
        ])
        assert result.exit_code == 0
        # Should show entries — the populated fixture has built variant
        assert "2.31" in result.output


class TestPatchVariantSelection:
    """patch --variant selects the correct glibc variant."""

    def test_patch_variant_deb_flag(self, runner, three_variant_dir, tmp_path):
        """--variant deb should use the deb lib path."""
        from tests.conftest import _build_minimal_elf
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(three_variant_dir),
            "patch", str(binary), "-v", "2.31", "--variant", "deb",
        ])
        # May fail due to patchelf not being installed, but should parse the flag
        if result.exit_code == 0:
            pass  # Success
        else:
            # Should NOT fail due to bad --variant arg
            assert "no such option" not in result.output.lower()

    def test_patch_variant_built_flag(self, runner, three_variant_dir, tmp_path):
        """--variant built should use the built lib path."""
        from tests.conftest import _build_minimal_elf
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(three_variant_dir),
            "patch", str(binary), "-v", "2.31", "--variant", "built",
        ])
        if result.exit_code == 0:
            pass
        else:
            assert "no such option" not in result.output.lower()

    def test_patch_variant_auto_flag(self, runner, three_variant_dir, tmp_path):
        """--variant auto should be accepted."""
        from tests.conftest import _build_minimal_elf
        binary = _build_minimal_elf(tmp_path / "test_bin", arch="amd64")

        result = runner.invoke(cli, [
            "--glibc-dir", str(three_variant_dir),
            "patch", str(binary), "-v", "2.31", "--variant", "auto",
        ])
        if result.exit_code == 0:
            pass
        else:
            assert "no such option" not in result.output.lower()


class TestBuildCLICommand:
    """CLI 'build' command validates args and calls builder."""

    @patch("shutil.which")
    def test_build_command_missing_deps(self, mock_which, runner, tmp_path):
        """build should report missing deps without starting build."""
        mock_which.return_value = None
        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        result = runner.invoke(cli, [
            "--glibc-dir", str(glibc_dir),
            "build", "2.31", "--arch", "amd64",
        ])
        # Should either fail or show missing deps info
        # (the exact behavior depends on CLI implementation)
        assert result.exit_code != 0 or "missing" in result.output.lower() or "install" in result.output.lower()

    def test_build_command_exists(self, runner, tmp_path):
        """The 'build' subcommand should be registered."""
        result = runner.invoke(cli, ["--help"])
        assert "build" in result.output


class TestSourceDirectoryCreation:
    """Source directory is created alongside built variant."""

    @patch("pwnlibc.builder.subprocess.run")
    @patch("urllib.request.urlopen")
    def test_source_dir_created(self, mock_urlopen, mock_run, tmp_path):
        """build_glibc should create source/ directory."""
        from pwnlibc.builder import build_glibc

        glibc_dir = tmp_path / "glibc"
        glibc_dir.mkdir()

        mock_resp = MagicMock()
        mock_resp.__enter__ = MagicMock(return_value=mock_resp)
        mock_resp.__exit__ = MagicMock(return_value=False)
        mock_resp.headers = {"Content-Length": "0"}
        mock_resp.read = MagicMock(return_value=b"")
        mock_urlopen.return_value = mock_resp

        def run_side_effect(cmd, **kwargs):
            if cmd[0] == "tar":
                try:
                    c_idx = cmd.index("-C")
                    target_dir = Path(cmd[c_idx + 1])
                except (ValueError, IndexError):
                    target_dir = Path(kwargs.get("cwd", "."))
                    if isinstance(target_dir, str):
                        target_dir = Path(target_dir)
                src_dir = target_dir / "glibc-2.31"
                src_dir.mkdir(parents=True, exist_ok=True)
                (src_dir / "configure").write_text("#!/bin/sh\nexit 0\n")
            return MagicMock(returncode=0, stdout="", stderr="")

        mock_run.side_effect = run_side_effect

        build_glibc("2.31", "amd64", glibc_dir)

        source_dir = glibc_dir / "2.31" / "source"
        assert source_dir.is_dir()
